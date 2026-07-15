# xpf Whole-Repository Defensive Audit 179

Base commit reviewed: `9bfd48226d023d9557c34eeaf634afe8fa7ea929`
Output path: `/tmp/codex-review-179.md`
Coordinator: `codex`
Mode: immutable, read-only, exact-once whole-tree Paladin campaign

## Executive Summary

This campaign reviewed all **2555** tracked Go, Rust, C/C++, header, and Python source files in **30** detached-worktree batches. After batch review, two-stage adjudication, prior-root-cause suppression, and coordinator verification, **129** non-duplicate findings remain.

Confidence: **126 High**, **3 Medium**, **0 Low**. Severity: **0 Critical**, **44 High**, **58 Medium**, **27 Low**. Lower-confidence items are triage candidates, not asserted production defects.

## Duplicate Suppression

The offline corpus covered **120** prior final reports and **18163** prior/repo tracking entries. Batch review produced **139** raw candidates; area adjudication dispositions were `{'DROP': 1, 'DUPLICATE': 3, 'MERGE': 3, 'RETAIN': 132}`; cross-area dispositions were `{'DROP': 2, 'MERGE': 1, 'RETAIN': 129}`; coordinator top-tier verification dropped **0** additional candidate(s).

Same-root findings were duplicates even when symptoms differed. Retention required a distinct invariant, root cause, affected path, or fix locus.

## Coverage Checklist

| Area | Files | Batches | Final findings | Scope |
|---|---:|---:|---:|---|
| A1 | 418 | 6 | 20 | Rust dataplane packet path and memory safety |
| A2 | 18 | 1 | 4 | Rust NAT, NAT64, NPTv6 and translation |
| A3 | 503 | 5 | 21 | Go configuration compiler, schema and CLI grammar |
| A4 | 63 | 1 | 10 | Configuration persistence and crypto at rest |
| A5 | 101 | 1 | 16 | HA, VRRP, RA and conntrack synchronization |
| A6 | 288 | 3 | 12 | Go dataplane manager and control publication |
| A7 | 272 | 3 | 15 | Daemon lifecycle and Linux host integration |
| A8 | 281 | 3 | 14 | gRPC, REST and management surfaces |
| A9 | 127 | 2 | 11 | Observability, telemetry and event processing |
| A10 | 484 | 5 | 7 | Services, CLI, build/deploy tooling and unmatched modules |
| **Total** | **2555** | **30** | **129** | Every source path exactly once |

Authoritative source-list SHA-256: `9cc7e8fbdbc6a048c1a03e0d419fd59429bb90b673c23343e60904b939903812`.

## Module-by-Module Inspection Log

### A1-b1: Rust dataplane packet path and memory safety (85 files)

Batch-list SHA-256: `9752e9f04c086c12a23f912c6d0e4b8c813ef158d261d1e4d0809fa2a9492a76`.

### Benchmarks, build, and C bridge

Dimensions checked: correctness/security and fail-closed behavior; memory safety, concurrency, truncation, and leaks; vSRX completeness where applicable; performance/latency; modularity and test gaps.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `userspace-dp/benches/prefix_set_lookup.rs` | Prefix-set benchmark | negative | Bench setup measures lookup work without changing semantics; no unbounded production work or misleading state reuse found. |
| `userspace-dp/benches/session_table.rs` | Session-table benchmark | negative | Key generation, table ownership, and hit/miss setup remain bounded and representative; no production safety surface. |
| `userspace-dp/benches/snat_allocator.rs` | SNAT allocator benchmark | negative | Port-range setup and allocation/release loop do not hide overflow, leak, or contention defects in the benchmarked contract. |
| `userspace-dp/benches/tx_kick_latency.rs` | TX-kick benchmark | negative | Ring/kick timing setup preserves descriptor ownership and does not count setup work as packet-path latency. |
| `userspace-dp/build.rs` | Native build integration | negative | Rebuild triggers, C compilation, and link directives are deterministic; no unsafe generated-source or ABI drift found. |
| `userspace-dp/csrc/xsk_bridge.c` | AF_XDP C bridge | negative | Pointer/ring bounds, ownership handoff, syscall errors, and integer widths were checked; no surviving memory-safety or truncation issue. |

### Core runtime, policy, and slow I/O

Dimensions checked: correctness/security and fail-closed policy behavior; memory/concurrency/partial-write/truncation/leak handling; vSRX policy completeness; hot-path allocation and contention; module boundaries and negative tests.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `userspace-dp/src/fairness.rs` | Fairness evaluator | negative | Weight normalization, empty inputs, bounded arithmetic, deterministic aggregation, and non-packet-path cost were checked. |
| `userspace-dp/src/fairness_tests.rs` | Fairness tests | negative | Boundary, skew, and aggregate fairness cases exercise the evaluator; no separate credible gap survived. |
| `userspace-dp/src/hot_hash_seed.rs` | Per-boot hot hash seed | negative | Entropy acquisition and fallback preserve stable-in-process but unpredictable-across-boot hashing without hot-path synchronization. |
| `userspace-dp/src/hot_hash_seed_tests.rs` | Hash-seed tests | negative | Seed stability and divergence contracts are covered; no deterministic attacker-controlled fallback found. |
| `userspace-dp/src/io_uring_write.rs` | io_uring packet write | negative (duplicate suppressed) | SQE/CQE identity, buffer lifetime, EINTR, partial writes, and demotion were traced; the stale-completion/error roots are already tracked by #2297/#2478. |
| `userspace-dp/src/io_uring_write_tests.rs` | io_uring write tests | negative (duplicate suppressed) | Stale CQE, completion matching, retry, and short-write regressions cover the known roots; no new one remained. |
| `userspace-dp/src/ip_proto.rs` | Protocol constants/classification | negative | Protocol-number aliases and family-independent comparisons are exact and allocation-free. |
| `userspace-dp/src/main.rs` | Process startup | negative | Argument/config validation, privilege/lifecycle ordering, fatal errors, and thread shutdown fail closed; no new startup race or leak found. |
| `userspace-dp/src/main_tests.rs` | Startup tests | negative | CLI/environment and startup failure cases match the runtime contract; no untested security-relevant branch survived review. |
| `userspace-dp/src/policy.rs` | Security policy engine | negative (duplicates suppressed) | Flow/flowless matching, L4-presence gates, fragments, counters, app IDs, PBR, and default policy were traced; related fragment roots are tracked by #2357/#3291/#3292/#4569. |
| `userspace-dp/src/policy_snapshot_error.rs` | Policy snapshot errors | negative | Error typing preserves transactional rejection context without silently accepting partial policy state. |
| `userspace-dp/src/policy_tests.rs` | Policy tests | negative | Positive/negative term matching, fragment fail-closed behavior, app/port constraints, and counters are broadly covered. |
| `userspace-dp/src/prefix.rs` | Prefix primitives | negative | Prefix-length bounds, masks, family separation, and containment arithmetic avoid shift/width errors. |
| `userspace-dp/src/prefix_set.rs` | Prefix-set runtime | negative | Immutable lookup structure, longest-match semantics, and construction-time allocation preserve bounded packet-path lookup. |
| `userspace-dp/src/prefix_set_tests.rs` | Prefix-set tests | negative | IPv4/IPv6 edge prefixes, overlap, and empty-set behavior are covered. |
| `userspace-dp/src/slowpath.rs` | TUN/slow-path writer | negative | Whole-packet semantics, nonblocking retry/drop behavior, fatal errno split, and fd ownership avoid remainder retransmission and leaks. |
| `userspace-dp/src/slowpath_tests.rs` | Slow-path tests | negative | EINTR, WouldBlock, partial packet, permanent error, and shutdown paths are exercised. |
| `userspace-dp/src/state_writer.rs` | State persistence writer | negative | Runtime io_uring demotion, write ordering, completion ownership, and sync fallback preserve durability; known demotion behavior is tracked. |
| `userspace-dp/src/state_writer_tests.rs` | State-writer tests | negative | Async/sync transitions, stale completions, and error fallback are covered without a new distinct defect. |
| `userspace-dp/src/tcp_flags.rs` | TCP flag helpers | negative | Bit masks and control/data eligibility predicates agree across cache/session consumers. |
| `userspace-dp/src/tcp_flags_tests.rs` | TCP flag tests | negative | SYN/ACK/FIN/RST/PSH combinations pin the intended eligibility matrix. |
| `userspace-dp/src/test_zone_ids.rs` | Test-only zone IDs | negative | Reserved/stable IDs do not collide with production sentinel ranges; test constants do not enter runtime. |

### XSK FFI, binding, and checksums

Dimensions checked: ABI correctness and fail-closed validation; raw-pointer/ring memory safety, atomics, truncation, and fd cleanup; vSRX dataplane applicability; per-packet syscall/cache cost; FFI modularity and tests.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `userspace-dp/src/xsk_ffi.rs` | Rust/C XSK FFI | negative | Layouts, pointer/null checks, ring indices, fd ownership, and narrowing conversions match the bridge ABI. |
| `userspace-dp/src/xsk_ffi_tests.rs` | XSK FFI tests | negative | Layout and error-path seams cover null/invalid handles and descriptor operations. |
| `userspace-dp/src/afxdp/bind.rs` | AF_XDP bind/prime | negative | UMEM frame accounting, ring reservations, busy-poll priming, retry bounds, and fd cleanup preserve ownership and startup latency. |
| `userspace-dp/src/afxdp/bpf_map_tests.rs` | BPF map integration tests | negative | Map key/value ABI, update flags, and error handling are covered; no silent partial publication found. |
| `userspace-dp/src/afxdp/checksum.rs` | Packet checksums | negative | One's-complement arithmetic, pseudo-headers, byte order, incremental repair, and BPF NAT-map calls were checked. |

### Telemetry, dispositions, events, and flow cache

Dimensions checked: forwarding correctness/security; atomic snapshots, overflow, truncation, and stale-state invalidation; vSRX observability; packet-path cacheline/allocation cost; separation of selection, action, and tests.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `userspace-dp/src/afxdp/cold_path_hist.rs` | Cold-path histogram | negative | Sampling, bucket arithmetic, seqlock publication, wrap handling, and bounded retries preserve low hot-path overhead. |
| `userspace-dp/src/afxdp/cold_path_hist_tests.rs` | Histogram tests | negative | Bucket boundaries, retries, snapshot consistency, and wrap cases are covered. |
| `userspace-dp/src/afxdp/disposition.rs` | Forwarding dispositions | negative | Terminal/nonterminal classification and status strings do not turn denial/error states into forwarding. |
| `userspace-dp/src/afxdp/ethernet.rs` | Ethernet/VLAN helpers | negative | Header lengths, VLAN-0 presence, EtherType byte order, and rewrite bounds are correct. |
| `userspace-dp/src/afxdp/event_emit.rs` | Dataplane events | negative | Event source/action attribution, rate limits, queue failures, and fixed-width encoding fail honestly without packet-path blocking. |
| `userspace-dp/src/afxdp/event_emit_tests.rs` | Event tests | negative | Policy/screen/filter event fields, limits, and failure accounting are covered. |
| `userspace-dp/src/afxdp/flow_cache.rs` | Worker flow cache | negative (duplicate suppressed) | Set/LRU invariants, generation/RG epoch invalidation, NAT family, neighbor-MAC epoch, and active-flow wrap were traced; out-of-range RG root is #2466. |
| `userspace-dp/src/afxdp/flow_cache_tests.rs` | Flow-cache tests | negative | Four-way LRU, eligibility, epoch wrap, stale MAC, NAT family, and observability limits have focused regressions. |
| `userspace-dp/src/afxdp/forward_request.rs` | Canonical forward-request builder | negative | This is the correct comparator for output-filter reject/log finalization; immediate and precomputed paths consume all `CoSTxSelection` action metadata. |

### GRE, HA, and ICMP

Dimensions checked: tunnel/HA/control-packet correctness and fail-closed behavior; parse/rewrite bounds, state ownership, atomics, and rate-limit leakage; vSRX GRE/HA/ICMP parity; encapsulation and control-path latency; focused module tests.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `userspace-dp/src/afxdp/gre.rs` | Native GRE decap/encap | A1-b1-F002 | Inner-family/header parsing, GRE options, endpoint matching, ECN, MTU, checksum, and synthetic metadata were traced; valid non-first inner fragments are rejected as fake L4. |
| `userspace-dp/src/afxdp/ha.rs` | HA runtime | negative (duplicate suppressed) | Lease expiry, activation/demotion, owner-RG propagation, epoch invalidation, shared-session poisoning recovery, and bounded prewarm were checked; out-of-range epoch root is #2466. |
| `userspace-dp/src/afxdp/ha_tests.rs` | HA tests | negative | Transition, lease, prewarm, poison recovery, generation, SNAT sync, export, and tunnel purge cases are covered. |
| `userspace-dp/src/afxdp/icmp.rs` | ICMP synthesis/translation | negative | Quote bounds, embedded flow/NAT repair, suppression, checksum, and family/type handling fail closed. |
| `userspace-dp/src/afxdp/icmp_ptb.rs` | PTB/Frag Needed | negative | Declared lengths, suppression classes, MTU floors, quotes, and transformed inner-MTU arithmetic are bounded and standards-aware. |
| `userspace-dp/src/afxdp/icmp_ptb_tests.rs` | PTB tests | negative | IPv4/IPv6, broadcasts/multicast, bad sources, transforms, padding, and per-peer WireGuard MTUs are covered. |
| `userspace-dp/src/afxdp/icmp_ratelimit.rs` | ICMP limiter | negative | Token accounting, keying, wrap/saturation, bounded map behavior, and thread ownership avoid amplification and contention. |
| `userspace-dp/src/afxdp/icmp_ratelimit_tests.rs` | ICMP limiter tests | negative | Burst/refill, family/type keys, expiry, and boundary behavior are exercised. |
| `userspace-dp/src/afxdp/icmp_tests.rs` | ICMP tests | negative | Reject, time-exceeded, NAT reversal, fragment suppression, checksums, and truncation have broad regression coverage. |

### Worker stages, neighbors, and parsing

Dimensions checked: stage-order security and fail-closed behavior; UMEM ownership, queue bounds, parser truncation, neighbor concurrency/leaks; vSRX filter/screen/NDP behavior; common-path allocation/locking; stage/parser modularity and test gaps.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `userspace-dp/src/afxdp/mod.rs` | AF_XDP coordinator/module root | negative | Global constants, worker orchestration, shared state ownership, and shutdown ordering remain bounded and fail closed. |
| `userspace-dp/src/afxdp/mpsc_inbox.rs` | Worker MPSC inbox | negative | Sequence/slot ownership, atomics, saturation, and producer/consumer visibility avoid overwrite and unbounded blocking. |
| `userspace-dp/src/afxdp/mpsc_inbox_tests.rs` | MPSC tests | negative | Full/empty, concurrent producer, ordering, wrap, and recovery cases are covered. |
| `userspace-dp/src/afxdp/neg_neigh.rs` | Negative neighbor cache | negative | TTL/capacity, monotonic time, bounded eviction, and keying do not create permanent false negatives. |
| `userspace-dp/src/afxdp/neighbor.rs` | Netlink neighbor monitor | negative (candidate refuted) | Multipart sequence/error handling and 8 KiB receives were traced; Linux caps `NLMSG_GOODSIZE` below 8 KiB specifically to avoid `MSG_TRUNC`. |
| `userspace-dp/src/afxdp/neighbor_dispatch.rs` | Neighbor learn/retry dispatch | A1-b1-F001 | Deferred packet ownership, timeout/recycle, live reclassification, NAT wire key, mirror/rewrite/TX routing were traced; reject/log output-filter metadata is discarded. |
| `userspace-dp/src/afxdp/neighbor_latency.rs` | Neighbor latency telemetry | negative | Bucket/time arithmetic and atomic snapshots are monotonic, bounded, and off the contended control socket. |
| `userspace-dp/src/afxdp/neighbor_resolver.rs` | Async neighbor resolver | negative (candidate refuted) | Request coalescing, queue bounds, GET reply classification, netlink reads, and shutdown were checked; 8 KiB is sufficient by the kernel contract. |
| `userspace-dp/src/afxdp/neighbor_resolver_tests.rs` | Resolver tests | negative | Dedup, retry, success/failure, queue pressure, and latency accounting are covered. |
| `userspace-dp/src/afxdp/parser.rs` | ARP/NDP parser | A1-b1-F003 | L2/VLAN, declared lengths, checksums, hop limit, options, and extension walking were traced; an IPv6 Fragment Header is accepted for NDP NA contrary to RFC 6980. |
| `userspace-dp/src/afxdp/parser_tests.rs` | Parser tests | negative (gap supports A1-b1-F003) | ARP/NDP truncation, VLAN, extension-chain, checksum, and validity tests are broad, but no Fragment-Header rejection test exists. |
| `userspace-dp/src/afxdp/poll_stages.rs` | Packet-stage pipeline | A1-b1-F003 | Stage order, link-layer learning, GRE handoff, flowless screens, SYN cookies, and IPsec admission were checked; accepted fragmented NA reaches neighbor publication. |
| `userspace-dp/src/afxdp/poll_stages_tests.rs` | Stage tests | negative (gap supports A1-b1-F003) | VLAN/zone, ARP/NDP learning, fragment screens, fabric skip, and IPsec cases are covered; fragmented NDP publication is not. |
| `userspace-dp/src/afxdp/rst.rs` | TCP RST synthesis | negative | RFC sequence/ack derivation, family/header bounds, checksums, and suppression avoid malformed active rejects. |

### Shared state, tunnel I/O, queues, and runtime

Dimensions checked: state/session/tunnel correctness and fail-closed behavior; mutex poison recovery, atomics, frame ownership, queue saturation, and leaks; vSRX tunnel/session parity; bounded scans and wake latency; modularity and integration tests.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `userspace-dp/src/afxdp/session_delta.rs` | Session delta encoding | negative | Open/close projection, NAT/session identity, generation, fixed widths, and loss accounting are consistent. |
| `userspace-dp/src/afxdp/sharded_neighbor.rs` | Sharded neighbor map | negative | Shard selection, lock scope, insert-if-changed epoch, removal, and snapshots avoid global contention and stale-MAC persistence. |
| `userspace-dp/src/afxdp/sharded_neighbor_tests.rs` | Sharded-neighbor tests | negative | Concurrent keys, same/different MAC epoch behavior, removal, and snapshots are covered. |
| `userspace-dp/src/afxdp/shared_ops.rs` | Shared session operations | negative | Poison recovery, lock ordering, index consistency, generation guards, and publish/delete symmetry were checked. |
| `userspace-dp/src/afxdp/shared_umem.rs` | Shared UMEM | negative | Single ownership, frame routing, registration, recycle validation, fallback, and atomics preserve no-double-free/no-leak invariants. |
| `userspace-dp/src/afxdp/shared_umem_tests.rs` | Shared-UMEM tests | negative | Group compatibility, fallback, slot routing, stale/unknown recycle, and ownership cases are covered. |
| `userspace-dp/src/afxdp/test_fixtures.rs` | AF_XDP fixtures | negative | Snapshot/packet fixtures preserve realistic ifindex, VLAN, MTU, tunnel, and checksum contracts. |
| `userspace-dp/src/afxdp/tests.rs` | AF_XDP integration tests | negative (gaps support A1-b1-F001/F002) | Full integration inventory was swept, including flowless policy/filter and pending-neighbor tests; no reject/log deferred-action or GRE inner-fragment regression exists. |
| `userspace-dp/src/afxdp/tunnel.rs` | Local tunnel thread/TX plan | negative (duplicate suppressed) | TUN fd lifecycle, wake/drain, session pruning, encap/MTU/CoS were checked; the local-origin reject-to-drop residual is already tracked in `docs/feature-gaps.md:527`. |
| `userspace-dp/src/afxdp/tunnel_tests.rs` | Tunnel tests | negative | Attachment rotation, stop/wake, whole-packet writes, GRE DSCP/ECN/MTU, and MSS formulas are covered; no separate retained root. |
| `userspace-dp/src/afxdp/worker_queue.rs` | Worker queue | negative | Capacity, ordering, wakeup, close, and ownership transfer remain bounded and nonblocking on the packet path. |
| `userspace-dp/src/afxdp/worker_queue_tests.rs` | Worker-queue tests | negative | Saturation, close/recovery, concurrent producer, and ordering cases are covered. |
| `userspace-dp/src/afxdp/worker_runtime.rs` | Worker runtime publication | negative | Atomic field ordering, snapshots, saturation, and aggregation avoid torn operator state and common-path locks. |
| `userspace-dp/src/afxdp/worker_runtime_tests.rs` | Runtime tests | negative | Publish/read, saturation, reset, and aggregation cases cover the atomic contract. |
| `userspace-dp/src/afxdp/zone_counters.rs` | Zone counters | negative | Stable zone IDs, atomic increments, snapshot/reset, overflow behavior, and sparse reporting are correct. |

### BPF map publication

Dimensions checked: fail-closed map behavior and ABI correctness; fd/key/value ownership, partial update/delete errors, and leaks; HA/vSRX session parity; syscall frequency; map-operation modularity and test coverage.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `userspace-dp/src/afxdp/bpf_map/ha.rs` | HA map operations | negative | Owner-RG gating and activation/demotion map operations do not replace locally active state or silently broaden forwarding. |
| `userspace-dp/src/afxdp/bpf_map/metrics.rs` | BPF map metrics | negative | Error/attempt counters are atomic, correctly attributed, and do not introduce per-packet control traffic. |
| `userspace-dp/src/afxdp/bpf_map/mod.rs` | BPF map root | negative | fd lifecycle, map ABI dispatch, and error propagation preserve one source of truth. |
| `userspace-dp/src/afxdp/bpf_map/pin.rs` | Pinned maps | negative | Open/create/type/size validation and cleanup refuse incompatible persistent maps without destructive reset. |
| `userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs` | Conntrack publication | negative | Forward/reverse key byte order, update flags, NAT fields, delete symmetry, and failure accounting were checked. |

### A1-b2: Rust dataplane packet path and memory safety (83 files)

Batch-list SHA-256: `bb56552540196bcfe1169aad81d965f8980390ceeb879ed2d4cef04906fc9412`.

All assigned files were read from the detached worktree. The ledger is numbered in batch order; every batch path appears exactly once.

### Coordinator and lifecycle

Dimension coverage:

| Dimension | Check and result |
|---|---|
| Correctness, security, fail-open | Traced map/build preflight, teardown, publication, worker/helper bring-up, status refresh, injection validation, neighbor ownership, HA state, GRE/WG lifecycle, and failure returns. A1-b2-F002 and A1-b2-F003 survive. |
| Memory, concurrency, truncation, leaks | Checked owned FD replacement, ArcSwap publication, stop/join ordering, mutex/atomic use, bounded warm queues, frame-length checks, thread tombstones, and stale-state cleanup. A1-b2-F002 leaves phantom live state after synchronous spawn failure; no unsafe-memory finding survived. |
| vSRX completeness | Reviewed HA forwarding leases, host injection, neighbor convergence, local GRE, and multi-peer WireGuard controls. Known WG timer/MTU gaps were duplicate-suppressed; no additional parity finding survived here. |
| Performance and latency | Checked control-socket work, bounded polling/backoff, status-buffer reuse, queue depths, and no per-packet logging in coordinator code. No new hot-path finding survived. |
| Modularity | The coordinator split preserves clear lifecycle ownership. The duplicated live-copy/unbound-zero field lists are a concrete maintenance fault in A1-b2-F003. |
| Tests and gaps | Existing tests strongly cover transactional map/build rejects and tunnel lifecycle. Missing injected spawn-failure tests and exhaustive copy-versus-zero parity tests permit A1-b2-F002/F003. |

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 001 | userspace-dp/src/afxdp/coordinator/bpf_maps.rs | BPF map ownership | negative | Required and optional map FDs remain owned, replaceable, and closed without publishing invalid handles. |
| 002 | userspace-dp/src/afxdp/coordinator/cos_leases.rs | Shared CoS leases | A1-b2-F001 | Lease construction/reuse, worker-slot sizing, shard accounting, and non-exact shared-lease attachment conserve credit across lifecycle changes. |
| 003 | userspace-dp/src/afxdp/coordinator/cos_state.rs | Shared CoS state | negative | ArcSwap maps initialize and clear coherently without stale owner or lease publication. |
| 004 | userspace-dp/src/afxdp/coordinator/ha_state.rs | HA runtime publication | negative | Watchdog timestamps, forwarding leases, RG epochs, and fabric updates do not create a new dual-primary or stale-state path. |
| 005 | userspace-dp/src/afxdp/coordinator/inject.rs | Packet injection | negative | Tuple version, protocol/family, destination, frame length, MTU, offsets, and ownership fail closed before injection. |
| 006 | userspace-dp/src/afxdp/coordinator/mod.rs | Coordinator lifecycle | negative | Initialization, stop ordering, shared-map reset, neighbor state, and control-plane publication remain coherent. |
| 007 | userspace-dp/src/afxdp/coordinator/neighbor_manager.rs | Neighbor manager state | negative | Warm queues are bounded, generation/rate-limit state is shared deliberately, and resolver lifetime has explicit ownership. |
| 008 | userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs | Worker/helper bring-up | A1-b2-F002 | A snapshot must not return success or publish live ownership when mandatory worker/helper threads did not spawn. |
| 009 | userspace-dp/src/afxdp/coordinator/reconcile/mod.rs | Reconcile transaction | A1-b2-F002 | Preflight, teardown, apply, bring-up, refresh, and Result propagation form one fail-closed transaction. |
| 010 | userspace-dp/src/afxdp/coordinator/reconcile/reset.rs | Binding reset | negative | Reset clears counters and binding flags without retaining packet or descriptor ownership. |
| 011 | userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs | Snapshot preflight/apply | negative | Mandatory/declared optional map opens and forwarding builds complete before teardown and generation publication. |
| 012 | userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs | Reconcile teardown | negative | Workers, tunnel sources, BPF handles, leases, and preserved sessions are stopped or transferred in bounded order. |
| 013 | userspace-dp/src/afxdp/coordinator/refresh_bindings.rs | Binding status refresh | A1-b2-F003 | Every mutable live-status field must be copied on live slots and cleared on workerless slots. |
| 014 | userspace-dp/src/afxdp/coordinator/session_manager.rs | Session coordination | negative | Replay, export acknowledgement, synchronized session ownership, and bounded status snapshots preserve generation semantics. |
| 015 | userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs | Same-plan refresh | negative | Fallible forwarding construction precedes validation/neighbor/tunnel publication, preserving atomic no-op on reject. |
| 016 | userspace-dp/src/afxdp/coordinator/status.rs | Status aggregation | negative | Sum/max/sentinel aggregation, histogram consistency, and shared atomic snapshots do not misattribute a surviving correctness issue. |
| 017 | userspace-dp/src/afxdp/coordinator/status_tests.rs | Status tests | negative | Status tests cover queue/worker aggregation and telemetry shape; no test implementation defect survived. |
| 018 | userspace-dp/src/afxdp/coordinator/supervisor.rs | Thread supervisor | A1-b2-F002 | The supervisor returns synchronous spawn errors and catches only post-spawn panics; callers must preserve that distinction. |
| 019 | userspace-dp/src/afxdp/coordinator/tests.rs | Coordinator regression tests | negative | Full 4,005-line suite inspected; it lacks deterministic worker/helper spawn-error injection and full unbound-field parity coverage. |
| 020 | userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs | GRE/WG thread lifecycle | negative | Attachment/identity/MTU restart, tombstone, backoff, join, and stop gates were traced; first-peer MTU candidate is already tracked under #2845. |
| 021 | userspace-dp/src/afxdp/coordinator/wg_control.rs | WireGuard control loop | negative | UDP/TUN bounds, per-peer endpoint selection, timers, poll errors, MTU guard, and send failures were traced; global-edge candidate is a tracked #1434/#1888 issue. |
| 022 | userspace-dp/src/afxdp/coordinator/wg_control_tests.rs | WireGuard control tests | negative | Timer, poll, packet-size, endpoint, and single-attempt behavior is covered; no new test-code defect survived. |
| 023 | userspace-dp/src/afxdp/coordinator/worker_manager.rs | Worker ownership | negative | Stop flags, handles, identity/live maps, panic slots, and joins clear without an independent lifecycle defect. |

### Class of service and TX scheduling

Dimension coverage:

| Dimension | Check and result |
|---|---|
| Correctness, security, fail-open | Traced admission through queue selection, guarantee/surplus service, token and vtime accounting, local/prepared submit, completion, refund, and recycle. A1-b2-F001 violates shared-credit conservation. |
| Memory, concurrency, truncation, leaks | Checked UMEM ownership transfer, prepared-frame recycling, pop/rollback snapshots, atomic lease ledgers, queue caps, saturating arithmetic, and reset drains. A1-b2-F001 strands outstanding credit; no raw-pointer or descriptor double-recycle finding survived. |
| vSRX completeness | Reviewed shaping, guarantees, exact caps, surplus sharing, ECN, fairness, and wakeup semantics. A1-b2-F001 can permanently violate the configured class guarantee after reset and is labeled vsrx-parity. |
| Performance and latency | Inspected hot-loop scans, allocations, atomics, cacheline isolation, timer-wheel work, queue locking, and batch bounds. The unbounded-command-queue candidate was refuted for the normal owner path by the bounded BindingLiveState inbox and drop-newest cap. |
| Modularity | Queue operations, service phases, token accounting, vtime, and completion are separated cleanly; the release helper's stale exact-only predicate is the cross-module drift in A1-b2-F001. |
| Tests and gaps | Broad unit coverage exists for admission, rollback, fairness, token refill, vtime, and completion. No test resets a backlogged non-exact shared-lease queue and asserts outstanding credit is returned. |

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 024 | userspace-dp/src/afxdp/cos/admission.rs | CoS admission | negative | Buffer/share limits, ECN marking, drop accounting, and prepared/local ownership remain bounded and fail closed. |
| 025 | userspace-dp/src/afxdp/cos/admission_tests.rs | Admission tests | negative | Exact/non-exact, ECN, flow-share, and buffer-limit regressions exercise the production admission predicates. |
| 026 | userspace-dp/src/afxdp/cos/builders.rs | Runtime builders | negative | Queue/runtime construction preserves configured rates, limits, ordering, and initial accounting state. |
| 027 | userspace-dp/src/afxdp/cos/builders_tests.rs | Builder tests | negative | Fixture construction covers queue shape and runtime initialization without masking a production defect. |
| 028 | userspace-dp/src/afxdp/cos/cross_binding.rs | Cross-binding redirect | negative | Local/prepared ownership transfer and recycle order are correct; normal owner redirects use the bounded live inbox. |
| 029 | userspace-dp/src/afxdp/cos/cross_binding_tests.rs | Cross-binding tests | negative | Owner, fallback, shared-exact, prepared-copy, and recycle cascades match production order. |
| 030 | userspace-dp/src/afxdp/cos/ecn.rs | ECN mutation | negative | Header bounds, ECT eligibility, checksum repair, and mark/drop accounting avoid malformed-frame writes. |
| 031 | userspace-dp/src/afxdp/cos/ecn_tests.rs | ECN tests | negative | IPv4/IPv6/VLAN and malformed/truncated frame cases cover the ECN mutation contract. |
| 032 | userspace-dp/src/afxdp/cos/fairness.rs | Flow fairness | negative | Fixed-point shares, active-flow accounting, and capped arithmetic do not introduce a new starvation or overflow path. |
| 033 | userspace-dp/src/afxdp/cos/flow_hash.rs | CoS flow hashing | negative | Tuple extraction and deterministic hashing remain bounded and stable across supported families. |
| 034 | userspace-dp/src/afxdp/cos/flow_hash_tests.rs | Flow-hash tests | negative | Family/protocol/fragment and determinism cases cover the hash input contract. |
| 035 | userspace-dp/src/afxdp/cos/mod.rs | CoS module surface | negative | Re-exports preserve one implementation source and do not fork accounting behavior. |
| 036 | userspace-dp/src/afxdp/cos/queue_ops/accounting.rs | Queue accounting | negative | Packet/byte/nonempty counters update with saturating, rollback-compatible semantics. |
| 037 | userspace-dp/src/afxdp/cos/queue_ops/active_buckets.rs | Active flow buckets | negative | Bucket activation/deactivation and bounded bitsets preserve cardinality and fairness state. |
| 038 | userspace-dp/src/afxdp/cos/queue_ops/drain.rs | Queue drain | negative | Drain paths consume or recycle each item once and do not leave rollback snapshots behind. |
| 039 | userspace-dp/src/afxdp/cos/queue_ops/fused_diff_tests.rs | Fused queue tests | negative | Differential tests pin fused operations against reference behavior. |
| 040 | userspace-dp/src/afxdp/cos/queue_ops/mod.rs | Queue-op dispatch | negative | Queue representations route through consistent push/pop/accounting helpers. |
| 041 | userspace-dp/src/afxdp/cos/queue_ops/pop.rs | Queue pop | negative | Pop snapshots, byte counters, flow buckets, and empty transitions stay reversible. |
| 042 | userspace-dp/src/afxdp/cos/queue_ops/pop_tests/mod.rs | Pop test module | negative | Test composition covers all pop representations without hidden production behavior. |
| 043 | userspace-dp/src/afxdp/cos/queue_ops/pop_tests/ordering.rs | Pop ordering tests | negative | FIFO/per-flow ordering and cursor advancement are stable. |
| 044 | userspace-dp/src/afxdp/cos/queue_ops/pop_tests/rollback.rs | Pop rollback tests | negative | Rollback restores item, counters, buckets, and ordering exactly once. |
| 045 | userspace-dp/src/afxdp/cos/queue_ops/pop_tests/snapshot_stack.rs | Snapshot-stack tests | negative | Snapshot depth remains batch-bounded and teardown uses the no-snapshot drain path. |
| 046 | userspace-dp/src/afxdp/cos/queue_ops/push.rs | Queue push | negative | Admission metadata, queued bytes, flow buckets, and ordering update atomically at the worker level. |
| 047 | userspace-dp/src/afxdp/cos/queue_ops/tests/admission.rs | Queue admission tests | negative | Push-side buffer and flow-share rejection preserves input ownership. |
| 048 | userspace-dp/src/afxdp/cos/queue_ops/tests/bench.rs | Queue-op benchmark tests | negative | Synthetic push/pop loops preserve queue state and do not hide a production-only ownership path. |
| 049 | userspace-dp/src/afxdp/cos/queue_ops/tests/bookkeeping.rs | Queue bookkeeping tests | negative | Tests pin runnable/nonempty counters, cursors, and byte totals against underflow or false work. |
| 050 | userspace-dp/src/afxdp/cos/queue_ops/tests/cap_aware.rs | Cap-aware queue tests | negative | Head length, root/queue tokens, hard caps, and batch budgets are exercised before service. |
| 051 | userspace-dp/src/afxdp/cos/queue_ops/tests/flow_fair_enable.rs | Flow-fair enable tests | negative | Mode-transition tests initialize and retire bucket state without losing queued ownership. |
| 052 | userspace-dp/src/afxdp/cos/queue_ops/tests/mod.rs | Queue-op tests | negative | Test composition covers admission, bookkeeping, caps, promotion, and fairness without a test-code defect. |
| 053 | userspace-dp/src/afxdp/cos/queue_ops/tests/promotion.rs | Promotion tests | negative | Promotion tests commit demand/vtime state without double service or stale participant publication. |
| 054 | userspace-dp/src/afxdp/cos/queue_ops/v_min.rs | V_min queue operations | negative | Epoch tags, per-worker slots, monotonic vtime, and shared floors use bounded atomic protocols. |
| 055 | userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/cadence.rs | V_min cadence tests | negative | Cadence, suspend, rejoin, and wrap tests exercise timing and sentinel boundaries. |
| 056 | userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/hard_cap.rs | V_min hard-cap tests | negative | Tests pin hard-cap overrides and generation checks against uncapped guarantee service. |
| 057 | userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/mod.rs | V_min test module | negative | Subtest composition covers the single promotion/throttle/vacate state machine. |
| 058 | userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/prepared_drain.rs | Prepared V_min drain tests | negative | Prepared descriptors are tested for exactly-once submit, refund, or recycle. |
| 059 | userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/publish.rs | V_min publication tests | negative | Atomic publication tags and values are tested as coherent peer-worker snapshots. |
| 060 | userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/rejoiner.rs | V_min rejoin tests | negative | Rejoining workers cannot publish stale epoch/vtime state as active demand. |
| 061 | userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/throttle.rs | V_min throttle tests | negative | Throttle tests preserve hard-cap and wakeup progress without permanent false suspension. |
| 062 | userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/vacate.rs | V_min vacate tests | negative | Participant slots are tested as vacated before runtime clear so peers cannot retain stale vtime. |
| 063 | userspace-dp/src/afxdp/cos/queue_service/drain.rs | Service drain loop | negative | Per-call work is batch-bounded and no-progress paths terminate without losing requests. |
| 064 | userspace-dp/src/afxdp/cos/queue_service/mod.rs | Queue service selector | negative | Exact, non-exact, and surplus phases maintain independent cursors and token gates. |
| 065 | userspace-dp/src/afxdp/cos/queue_service/service.rs | Service transaction | negative | Selected batches flow through submit and completion accounting with rollback on partial progress. |
| 066 | userspace-dp/src/afxdp/cos/queue_service/submit_local.rs | Local submit | negative | Local frame ownership, TX-ring capacity, and retry requests remain bounded. |
| 067 | userspace-dp/src/afxdp/cos/queue_service/submit_prepared.rs | Prepared submit | negative | UMEM descriptors survive partial submit and recycle only after completion or explicit drop. |
| 068 | userspace-dp/src/afxdp/cos/queue_service/tests/drain.rs | Drain tests | negative | Budget/no-progress/partial-send tests cover drain termination and accounting. |
| 069 | userspace-dp/src/afxdp/cos/queue_service/tests/mod.rs | Service integration tests | negative | Cross-phase integration tests exercise ordering, caps, fairness, and wakeups. |
| 070 | userspace-dp/src/afxdp/cos/queue_service/tests/refund.rs | Refund/lease tests | negative | Tests pin phase-aware root/queue refunds and prevent credit creation on failed submits. |
| 071 | userspace-dp/src/afxdp/cos/queue_service/tests/selector.rs | Selector tests | negative | Round-robin, guarantee, and surplus selection are tested for bounded progress and starvation. |
| 072 | userspace-dp/src/afxdp/cos/queue_service/tests/sojourn.rs | Sojourn tests | negative | Tests cover monotonic timestamps, window/EWMA updates, and sampling boundaries. |
| 073 | userspace-dp/src/afxdp/cos/queue_service/tests/submit.rs | TX submit tests | negative | Ring reservation, partial writes, retry ordering, owner routing, and ownership are exercised. |
| 074 | userspace-dp/src/afxdp/cos/queue_service/tests/wakeup.rs | Wakeup tests | negative | Tick estimation, wrap, parked membership, and runnable restore avoid lost wakeups. |
| 075 | userspace-dp/src/afxdp/cos/queue_service/tests/waterfill.rs | Waterfill tests | negative | Phase budgets, honored masks, minimum quanta, and no-progress termination are covered. |
| 076 | userspace-dp/src/afxdp/cos/token_bucket.rs | Token/lease accounting | A1-b2-F001 | Every shared queue-lease grant must be consumed or released before local token state is discarded. |
| 077 | userspace-dp/src/afxdp/cos/token_bucket_tests.rs | Token-bucket tests | negative | Refill precision, exact/v8 acquire, non-exact fallback, and caps are covered; reset give-back is not. |
| 078 | userspace-dp/src/afxdp/cos/tx_completion.rs | Completion accounting | A1-b2-F001 | Normal empty-queue completion returns unused exact and non-exact shared credit, exposing the reset-path asymmetry. |
| 079 | userspace-dp/src/afxdp/cos/tx_completion_tests.rs | Completion tests | negative | Phase debit/refund and empty-queue return tests pass conceptually but do not invoke runtime reset. |

### Forwarding and host inbound

Dimension coverage:

| Dimension | Check and result |
|---|---|
| Correctness, security, fail-open | Traced destination parsing, route/next-table resolution, local delivery, HA/fabric disposition, IPsec classification, and host-inbound token evaluation. The IKE candidate is the already tracked #3616/#4323 root and was suppressed. |
| Memory, concurrency, truncation, leaks | Checked frame-slice bounds, IPv4/IPv6 offsets, UDP/IKE minimum lengths, neighbor map reads, recursion depth, and route candidate handling. No unsafe-memory or truncation finding survived. |
| vSRX completeness | Reviewed host-inbound services/protocols and IPsec passthrough semantics against documented parity work. No new non-duplicate gap survived. |
| Performance and latency | Route tables and hot lookup loops were checked for unbounded work and repeated allocation; no retained performance finding. |
| Modularity | Host-inbound token matching is isolated from forwarding resolution; no divergent duplicate implementation was found. |
| Tests and gaps | The 4,668-line forwarding suite and host-inbound tests cover route, NAT-local, ECMP, tunnel, malformed packet, and token cases. No distinct test gap rose to a finding. |

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 080 | userspace-dp/src/afxdp/forwarding/host_inbound.rs | Host-inbound policy | negative | Zone lookup, service/protocol tokens, family-specific matching, and unknown-token handling do not create a new fail-open path. |
| 081 | userspace-dp/src/afxdp/forwarding/host_inbound_tests.rs | Host-inbound tests | negative | Service/protocol, family, zone, wildcard, and deny cases exercise the policy helper. |
| 082 | userspace-dp/src/afxdp/forwarding/mod.rs | Forwarding core | negative | Frame parsing, route/ECMP/next-table, local/NAT delivery, HA/fabric, neighbor, tunnel, and IPsec decisions remain bounded; IKE residual is duplicate-suppressed. |
| 083 | userspace-dp/src/afxdp/forwarding/tests.rs | Forwarding tests | negative | Full 4,668-line suite inspected; regressions cover route scope/preference, ECMP liveness, local delivery, IPsec recognition, and malformed state. |

### A1-b3: Rust dataplane packet path and memory safety (67 files)

Batch-list SHA-256: `5b254e7ec364c2dbd4de9ecf3a73412b1c682a2fae7001c0056a88c7c88b3649`.

Ledger shorthand: **C/S** = correctness, security, and fail-closed behavior; **M** = memory safety, concurrency, truncation, ownership, and leaks; **V** = vSRX/feature parity; **P** = packet-path latency, allocation, locking, and boundedness; **D/T** = modularity, contracts, and negative-test coverage. Every row records all five dimensions and every assigned path appears exactly once.

### Forwarding snapshot build

| Path | Result | Invariant checked across C/S, M, V, P, D/T |
|---|---|---|
| `userspace-dp/src/afxdp/forwarding_build/cos.rs` | negative | **C/S:** queue/classifier/rewrite values remain bounded and unresolved references degrade to safe defaults; **M:** owned maps and narrowing conversions checked; **V:** scheduler/classifier semantics compared with snapshot intent; **P:** build-time only, no packet allocations; **D/T:** isolation tests cover malformed priorities, queue ids, and classifiers. |
| `userspace-dp/src/afxdp/forwarding_build/fib.rs` | negative | **C/S:** family, preference, gateway, connected, ECMP, and route-table construction checked for fail-closed behavior; **M:** parsing and integer conversions are bounded; **V:** route preference/table behavior reviewed; **P:** all scans are snapshot-time; **D/T:** contradictory-family and negative-preference tests survive. |
| `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` | negative | **C/S:** logical/VLAN identity, MAC, MTU, addresses, connected routes, and zone references checked; **M:** no borrowed snapshot data escapes; **V:** logical-unit and host-local semantics reviewed; **P:** build-only maps; **D/T:** invalid VLAN/MTU/address and logical-unit tests cover the boundaries. |
| `userspace-dp/src/afxdp/forwarding_build/mod.rs` | negative | **C/S:** pass ordering and `Result` propagation preserve transactional snapshot publication; **M:** prior-state reuse does not expose mutable aliases; **V:** all forwarding sub-builders are wired; **P:** work remains off the packet path; **D/T:** top-level state tests cover pass dependencies and prior-state reuse. |
| `userspace-dp/src/afxdp/forwarding_build/tests.rs` | `A1-b3-F005` | **C/S:** broad fail-closed snapshot tests pass, but WG fixtures expose the zero-destination/physical-resolution split used by F005; **M:** fixture ownership is safe; **V:** route, zone, CoS, and WG parity exercised; **P:** no hot-path benchmark claim inferred from unit tests; **D/T:** no real direct-WG TX-target/L2 integration test. |
| `userspace-dp/src/afxdp/forwarding_build/tunnels.rs` | `A1-b3-F005` | **C/S:** TTL, kind dispatch, key hydration, and endpoint indexes checked; WG endpoint-level destination is deliberately unspecified, feeding F005; **M:** key material uses `Zeroizing`; **V:** GRE/WG mode behavior reviewed; **P:** hydration is snapshot-time; **D/T:** tests validate keys/TTL but not complete WG outer forwarding resolution. |
| `userspace-dp/src/afxdp/forwarding_build/validated.rs` | negative | **C/S:** typed range conversions reject wrap/narrowing; **M:** no unsafe state; **V:** accepted ranges match published wire types; **P:** build-time only; **D/T:** boundary tests are present in the parent suite. |
| `userspace-dp/src/afxdp/forwarding_build/wg.rs` | negative | **C/S:** identity-stable engine reuse and high-water transfer preserve anti-replay state; **M:** Arc/Zeroizing ownership checked; **V:** multi-peer identity fields included; **P:** unchanged engines avoid reload churn; **D/T:** reload and anti-replay carry-forward tests cover both rebuild branches. |
| `userspace-dp/src/afxdp/forwarding_build/zones.rs` | negative | **C/S:** reserved/duplicate IDs and unknown zone references fail closed; **M:** maps own names and ids; **V:** zone-zero/default-deny behavior reviewed; **P:** build-only; **D/T:** reserved, duplicate, absent, and host-inbound cases are tested. |

### Frame parsing, building, rewriting, TCP, and WG

| Path | Result | Invariant checked across C/S, M, V, P, D/T |
|---|---|---|
| `userspace-dp/src/afxdp/frame/build/ipv4.rs` | `A1-b3-F003` | **C/S:** TTL/NAT/port/checksum order reviewed; full tunnel L4 recompute is gated only on non-first fragments, not all fragments; **M:** slice guards prevent OOB; **V:** fragmented tunnel transit is broken; **P:** straight-line hot leaf; **D/T:** only non-first-fragment regression exists. |
| `userspace-dp/src/afxdp/frame/build/ipv6.rs` | `A1-b3-F003` | **C/S:** hop-limit, ext-aware L4, NAT, and checksum order reviewed; first fragments still reach forced full recompute; **M:** offset walkers are bounds-checked; **V:** IPv6 fragment forwarding parity affected; **P:** hot leaf remains allocation-free; **D/T:** no offset-zero/M-bit fragment test. |
| `userspace-dp/src/afxdp/frame/build/mod.rs` | negative | **C/S:** L2 prelude, NAT-on-fabric, MSS, payload copy, and tunnel dispatch checked; **M:** destination capacities and checked sizes are enforced; **V:** GRE/WG typed dispatch fails closed; **P:** one caller-provided buffer; **D/T:** family leaves contain the surviving fragment issue. |
| `userspace-dp/src/afxdp/frame/byte_writes.rs` | negative | **C/S:** endian-correct fixed-offset IP/port writes checked; **M:** all writes use guarded slices; **V:** wire layout matches protocol headers; **P:** tiny inline kernels; **D/T:** exact offset and truncation tests present. |
| `userspace-dp/src/afxdp/frame/byte_writes_tests.rs` | negative | **C/S:** v4/v6 address and TCP/UDP port golden offsets checked; **M:** short-frame no-write cases covered; **V:** network-byte-order output pinned; **P:** no irrelevant allocation assertion; **D/T:** focused negative coverage is adequate. |
| `userspace-dp/src/afxdp/frame/checksum.rs` | negative | **C/S:** one's-complement folding, pseudo-headers, zero canonicalization, and incremental deltas checked; **M:** vectorized paths retain length guards; **V:** v4/v6 checksum rules reviewed; **P:** AVX2/scalar selection avoids packet allocation; **D/T:** independent scalar/golden tests cover key formulas. |
| `userspace-dp/src/afxdp/frame/generated.rs` | negative | **C/S:** generated-reply tuple parsing honors declared IP length and protocol gates; **M:** all offsets are checked; **V:** ICMP/TCP/UDP generated replies reviewed; **P:** parser is allocation-free; **D/T:** truncated and declared-short fixtures cover both families. |
| `userspace-dp/src/afxdp/frame/generated_tests.rs` | negative | **C/S:** reply tuple/DSCP/VLAN behavior and declared-length rejection checked; **M:** every truncation boundary returns `None`; **V:** v4/v6 protocol variants covered; **P:** no hot-path regression inferred; **D/T:** negative matrix is concrete and symmetric. |
| `userspace-dp/src/afxdp/frame/headers.rs` | negative | **C/S:** Ethernet/VLAN/IP/UDP serialization and TTL defaults checked; **M:** short output slices fail; **V:** TPID/TCI and IPv6 fields match wire semantics; **P:** direct writes; **D/T:** golden and short-buffer tests present. |
| `userspace-dp/src/afxdp/frame/headers_tests.rs` | negative | **C/S:** checksums, DF, TOS, flow label, VLAN0/802.1ad, and UDP values pinned; **M:** short buffers covered; **V:** tagged-wire parity exercised; **P:** N/A for fixtures; **D/T:** broad boundary coverage. |
| `userspace-dp/src/afxdp/frame/inspect.rs` | negative (duplicate suppressed) | **C/S:** L2/L3/L4, extension, fragment, flex, and declared-end parsing reviewed; the metadata-complete TCP/UDP early return bypasses the declared-end hardening, but this is the same root as tracked `#2361`; **M:** walkers are bounded; **V:** flowless fragment semantics reviewed; **P:** metadata shortcut is hot; **D/T:** fallback tests leave metadata ports zero and miss that duplicate condition. |
| `userspace-dp/src/afxdp/frame/inspect_tests.rs` | negative (duplicate suppressed) | **C/S:** frame-led and live-port helpers reject trailing bytes beyond IP length; **M:** truncation cases are safe; **V:** v4/v6 behavior symmetric; **P:** test-only; **D/T:** complete-metadata `parse_session_flow_from_bytes` case is absent, but belongs to tracked `#2361`. |
| `userspace-dp/src/afxdp/frame/mod.rs` | `A1-b3-F001`, `A1-b3-F003` | **C/S:** build/rewrite/NAT/tunnel orchestration traced through TX; **M:** shared-`MmapArea` mutation and failure ordering violate the alias/fallback contract (F001); first-fragment forced recompute is exposed through family leaves (F003); **V:** fragment transit impacted; **P:** in-place optimization is hot; **D/T:** tests explicitly ratify pre-failure L2 mutation but do not test caller reuse. |
| `userspace-dp/src/afxdp/frame/prop_tests/inspect.rs` | negative | **C/S:** garbage, malformed extension chains, metadata independence, and first/non-first fragment pins reviewed; **M:** parser no-panic and offset bounds covered; **V:** extension variants included; **P:** property tests only; **D/T:** generators do not challenge complete metadata against a short declared datagram. |
| `userspace-dp/src/afxdp/frame/prop_tests/mod.rs` | negative | **C/S:** property suites are wired and case counts bounded; **M:** environment parsing does not affect production; **V:** v4/v6 suites enabled; **P:** test runtime configurable; **D/T:** module coverage inventory completed. |
| `userspace-dp/src/afxdp/frame/prop_tests/oracle.rs` | negative | **C/S:** independent packet/checksum tuple oracle reviewed; **M:** checked parsing prevents test-oracle OOB; **V:** both families/protocols represented; **P:** test-only allocation acceptable; **D/T:** oracle assumes internally consistent IP lengths. |
| `userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs` | `A1-b3-F001` | **C/S:** descriptor/generic parity, NAT, TTL, extensions, and checksum properties reviewed; **M:** test comment confirms L2 is mutated before `None`; **V:** rewrite parity broad; **P:** differential tests do not model live caller borrowing; **D/T:** the “caller drops” assumption is contradicted by F001's callers. |
| `userspace-dp/src/afxdp/frame/prop_tests/segment.rs` | `A1-b3-F002`, `A1-b3-F003` | **C/S:** valid-packet reassembly/NAT/SYN-FIN-RST refusal checked; **M:** garbage no-panic property present; **V:** v4/v6 extension segmentation covered; **P:** output growth is bounded for valid generators; **D/T:** no declared-short backing frame or first-fragment strategy. |
| `userspace-dp/src/afxdp/frame/prop_tests/strategies.rs` | `A1-b3-F002`, `A1-b3-F003` | **C/S:** generated packet lengths/checksums are internally consistent, which masks F002/F003; **M:** generator bounds are finite; **V:** families/protocols/extensions represented; **P:** test-only; **D/T:** malformed declared-length and offset-zero fragmented variants are missing. |
| `userspace-dp/src/afxdp/frame/rewrite/ipv4.rs` | `A1-b3-F001` | **C/S:** descriptor TTL, NAT, port/checksum deltas reviewed; fallible checks occur after L2 mutation in the orchestrator; **M:** leaf slices are guarded but alias ownership is not; **V:** IPv4 rewrite semantics otherwise match generic; **P:** branch-minimized hot leaf; **D/T:** mismatch tests ignore whole-frame rollback/fallback. |
| `userspace-dp/src/afxdp/frame/rewrite/ipv6.rs` | `A1-b3-F001` | **C/S:** v6 descriptor offsets/NAT/checksum logic reviewed; late failure shares F001 ordering; **M:** bounds are safe locally but mutable alias contract is external; **V:** extension/NPTv6 parity checked; **P:** hot leaf; **D/T:** no caller-level failure reuse test. |
| `userspace-dp/src/afxdp/frame/rewrite/mod.rs` | `A1-b3-F001` | **C/S:** descriptor eligibility, family dispatch, fragment fallback, and result construction checked; Ethernet mutation precedes fragment/family/leaf validation; **M:** creates mutable UMEM slice from shared area; **V:** descriptor/generic parity intended; **P:** no-copy fast path; **D/T:** differential suite validates bytes only after success. |
| `userspace-dp/src/afxdp/frame/tcp.rs` | negative | **C/S:** reject RST, SYN-cookie replies, TCP flags/window, and MSS parsing/clamping checked; **M:** option walkers and truncation gates are bounded; **V:** RST/SYN semantics reviewed; **P:** no allocation in inspectors; **D/T:** broadcast/group guard is tracked under `#3204`, so no duplicate retained. |
| `userspace-dp/src/afxdp/frame/tcp_segmentation.rs` | `A1-b3-F002`, `A1-b3-F003` | **C/S:** segmentation uses physical tail instead of IP-declared end (F002) and treats first fragments as complete TCP datagrams (F003); **M:** local indexing is checked but output amplification follows attacker-visible length; **V:** PMTU/fragment forwarding broken; **P:** allocates one `Vec` per emitted segment; **D/T:** malformed-length/first-fragment tests absent. |
| `userspace-dp/src/afxdp/frame/tcp_tests.rs` | negative | **C/S:** TCP flags, reject, cookie, option, and MSS boundaries reviewed; **M:** truncated options/headers fail safely; **V:** TCP control behavior covered; **P:** test-only; **D/T:** no independent issue beyond segmentation files. |
| `userspace-dp/src/afxdp/frame/tests.rs` | `A1-b3-F002`, `A1-b3-F003` | **C/S:** large integration suite covers NAT, VLAN, tunnel, segmentation, TTL, and fragment predicates; **M:** in-place fixtures use owned areas safely; **V:** broad v4/v6/GRE behavior; **P:** no malformed output-amplification case; **D/T:** test names prove only non-first tunnel fragment and internally valid segmentation are pinned. |
| `userspace-dp/src/afxdp/frame/wg.rs` | `A1-b3-F005` | **C/S:** peer LPM, crypto, MTU, source, UDP checksum, and outer framing checked; selected-peer route is used only for MTU/source while TX target and L2 come from stale/logical decision state; **M:** encryption staging and output bounds are safe; **V:** direct AF_XDP WG route is incomplete; **P:** route resolve is once per packet; **D/T:** tests inject MACs rather than derive full underlay resolution. |
| `userspace-dp/src/afxdp/frame/wg_tests.rs` | `A1-b3-F005` | **C/S:** tests prove real WG admit resolution has `tx_ifindex=0`/logical egress, then fabricate MACs to exercise the builder; **M:** crypto fixtures are owned; **V:** source/MTU tests cover only part of outer resolution; **P:** one-LPM canary passes; **D/T:** no target-binding plus peer-route L2 end-to-end test. |

### Embedded ICMP NAT reversal

| Path | Result | Invariant checked across C/S, M, V, P, D/T |
|---|---|---|
| `userspace-dp/src/afxdp/icmp_embed/builders.rs` | `A1-b3-F004` | **C/S:** outer/quoted address/port restoration and checksum order reviewed; prebuilt forwarded errors never decrement outer TTL/hop-limit (F004); **M:** allocations and slices are bounded; **V:** routed ICMP error semantics affected; **P:** one owned frame on rare error path; **D/T:** no TTL/hop-limit assertions. |
| `userspace-dp/src/afxdp/icmp_embed/mod.rs` | `A1-b3-F004` | **C/S:** family dispatch and wrappers traced into the prebuilt builder; **M:** frame slices remain borrowed read-only here; **V:** both families wired; **P:** thin wrappers; **D/T:** no module-level TTL test. |
| `userspace-dp/src/afxdp/icmp_embed/nat_match_v4.rs` | negative (duplicate suppressed) | **C/S:** quoted v4 lookup/NAT reversal/return resolution reviewed; pure-DNAT caller gating maps to tracked `#3112`; **M:** parser bounds checked; **V:** SNAT/DNAT tuple restoration considered; **P:** cold error path; **D/T:** duplicate root not re-reported. |
| `userspace-dp/src/afxdp/icmp_embed/nat_match_v6.rs` | negative (duplicate suppressed) | **C/S:** v6 quoted extension/fragment/NAT matching reviewed; known parser-alignment roots map to `#4533`; **M:** bounded extension walk; **V:** ICMPv6 parity reviewed; **P:** bounded eight-header walk; **D/T:** no new root survived. |
| `userspace-dp/src/afxdp/icmp_embed/parse.rs` | negative (duplicate suppressed) | **C/S:** outer/quoted header and identifier handling checked; generic ICMP pseudo-port concern maps to tracked `#3067`, ext-walk concern to `#4533`; **M:** no OOB found; **V:** v4/v6 quote parsing reviewed; **P:** fixed walk bound; **D/T:** known-root candidates suppressed. |
| `userspace-dp/src/afxdp/icmp_embed/return_resolution.rs` | negative | **C/S:** reverse-session-first then live-route fallback checked; **M:** no lock held across route lookup; **V:** HA return resolution reviewed; **P:** error-path lookup only; **D/T:** behavior exercised indirectly by NAT match tests. |
| `userspace-dp/src/afxdp/icmp_embed/session_match.rs` | negative | **C/S:** quoted tuple to forward/reverse session-key matching checked; **M:** no unsafe or retained borrow; **V:** NAT and no-NAT sessions considered; **P:** bounded map lookups; **D/T:** no non-duplicate mismatch survived. |

### Port mirroring

| Path | Result | Invariant checked across C/S, M, V, P, D/T |
|---|---|---|
| `userspace-dp/src/afxdp/mirror/fast_path.rs` | negative | **C/S:** sampling/admission and exact-queue ownership checked; **M:** cloned frame ownership and queue failure paths recycle correctly; **V:** ingress/logical selection reviewed; **P:** admission precedes clone and queue bounds are constant; **D/T:** interleaving/full-queue tests present. |
| `userspace-dp/src/afxdp/mirror/mod.rs` | negative | **C/S:** config selection, sampling, target resolution, and result counters checked; **M:** no shared mutable frame aliases introduced; **V:** parent/logical interface fallback covered; **P:** no clone before admission; **D/T:** child tests cover missing target and frame bounds. |
| `userspace-dp/src/afxdp/mirror/mod_tests.rs` | negative | **C/S:** cross-binding, queue exactness, ownership, counters, and sampled behavior exercised; **M:** queue-full paths retain ownership; **V:** logical VLAN cases included; **P:** reserve-before-clone behavior pinned; **D/T:** coverage is concrete. |
| `userspace-dp/src/afxdp/mirror/resolver.rs` | negative | **C/S:** output logical-to-physical binding resolution and queue choice checked; **M:** immutable lookup only; **V:** multiqueue behavior reviewed; **P:** bounded map lookups; **D/T:** direct resolver cases exist in mirror tests. |

### Poll descriptor and generated replies

| Path | Result | Invariant checked across C/S, M, V, P, D/T |
|---|---|---|
| `userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs` | negative | **C/S:** cookie ACK/RST generation, TX budget, filters, and logical ingress checked; **M:** owned reply transfer/recycle paths safe; **V:** active reply behavior reviewed; **P:** build is gated by budget; **D/T:** VLAN/filter/budget tests present. |
| `userspace-dp/src/afxdp/poll_descriptor/cookie_reply_tests.rs` | negative | **C/S:** batch reserve, output-filter drop, VLAN logical classification, and enqueue metadata tested; **M:** fixture queues preserve ownership; **V:** generated reply classification covered; **P:** reserve behavior pinned; **D/T:** focused suite adequate. |
| `userspace-dp/src/afxdp/poll_descriptor/debug_log_throttle.rs` | negative | **C/S:** diagnostics do not alter forwarding; **M:** no unsafe state; **V:** N/A; **P:** bounded/throttled logging and wrapping counters checked; **D/T:** simple helper contract is explicit. |
| `userspace-dp/src/afxdp/poll_descriptor/filter.rs` | negative | **C/S:** input/PBR/lo0/output filter verdict, logging, and counter ordering checked; **M:** borrowed match extras do not escape; **V:** Junos filter stages reviewed; **P:** cached/precomputed paths avoid repeated work; **D/T:** no new bypass survived. |
| `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` | `A1-b3-F001` | **C/S:** cache validation, policy/filter counters, mirroring, rewrite, enqueue, and recycle traced; **M:** live shared `packet_frame` is reused after unsafe in-place mutation failure; **V:** normal cached forwarding affected; **P:** highest-rate path; **D/T:** no caller-level failed-rewrite test. |
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | `A1-b3-F001`, `A1-b3-F004` | **C/S:** full RX metadata-to-policy/session/NAT/build/enqueue/recycle chain inspected; raw-frame lifetime feeds F001 and embedded-ICMP prebuilt enqueue feeds F004; **M:** descriptor ownership/recycling exits audited; **V:** flowless, HA, NAT64, host, and tunnel branches reviewed; **P:** logging/locks/allocations checked; **D/T:** large inline suite does not cover either surviving cross-stage contract. |
| `userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs` | negative | **C/S:** source-NAT failure attribution and drop behavior checked; **M:** no retained allocations on error; **V:** operator counters distinguish causes; **P:** logging is gated to exception path; **D/T:** no new root. |
| `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` | negative (duplicate suppressed) | **C/S:** TCP/ICMP reject feasibility, output filter, rate limit, and queue budget checked; **M:** owned reply failure paths safe; **V:** reject semantics reviewed; **P:** build-before-token behavior is explicitly tracked under `#3656`; **D/T:** source/L2 concern maps to `#3204`. |
| `userspace-dp/src/afxdp/poll_descriptor/reject_reply_tests.rs` | negative (duplicate suppressed) | **C/S:** reject tuple, NAT, VLAN, filter, budget, and rate counters broadly tested; **M:** ownership/drop cases covered; **V:** both families/actions represented; **P:** existing consumption-order tests correspond to `#3656`; **D/T:** no new independent defect. |
| `userspace-dp/src/afxdp/poll_descriptor/rx_telemetry.rs` | negative | **C/S:** metadata/disposition counters and descriptor telemetry checked; **M:** atomics are relaxed counters without synchronization semantics; **V:** observability surfaces considered; **P:** sampled/constant-time stores; **D/T:** no correctness dependency on counter freshness. |

### Session glue and HA worker commands

| Path | Result | Invariant checked across C/S, M, V, P, D/T |
|---|---|---|
| `userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs` | negative | **C/S:** table/map deletion and SNAT/NAT64 reservation release order checked; **M:** cloned lookup precedes delete; **V:** peer-synced teardown converges; **P:** command path only; **D/T:** delete-sync tests cover poisoned queues and reservations elsewhere. |
| `userspace-dp/src/afxdp/session_glue/commands/demote_owner_rgs.rs` | negative | **C/S:** deduped RG demotion, live re-resolution, HA enforcement, republish, and cancellation checked; **M:** no stale references across table refresh; **V:** split-RG/fabric behavior covered; **P:** bounded by sessions in transitioned RG, off packet path; **D/T:** demotion and epoch tests broad. |
| `userspace-dp/src/afxdp/session_glue/commands/export_owner_rg_sessions.rs` | negative | **C/S:** command records union and sequences without overflowing delta ring; **M:** owned vectors; **V:** HA bulk snapshot semantics reviewed; **P:** chunked drain delegated to worker loop; **D/T:** >ring-cap regression exists. |
| `userspace-dp/src/afxdp/session_glue/commands/mod.rs` | negative | **C/S:** handler surface and test-only export checked; **M:** no independent state; **V:** all nontrivial command variants wired; **P:** thin dispatch; **D/T:** visibility keeps tests aligned with production helper. |
| `userspace-dp/src/afxdp/session_glue/commands/refresh_owner_rgs.rs` | negative | **C/S:** all HA-managed sessions are re-resolved for split-RG moves and local-delivery publish posture; **M:** collect-then-mutate avoids iterator invalidation; **V:** standby/active local delivery covered; **P:** transition-only full scan; **D/T:** `#4805` tests cover both states. |
| `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs` | negative | **C/S:** peer resolution, local-clobber gate, NAT/NAT64 reservation, and publish ordering checked; **M:** cloned metadata/key avoid use-after-move; **V:** standby readiness and active enforcement reviewed; **P:** control path; **D/T:** translated/synced/failover tests present. |
| `userspace-dp/src/afxdp/session_glue/mod.rs` | negative | **C/S:** cache/live re-resolution, tunnel-id ownership, command draining, publication, materialization, promotion, and HA redirect traced; **M:** queue poison recovery and session-table mutation ordering checked; **V:** split RG/fabric/local delivery covered; **P:** empty command queue uses `try_lock`, packet lookup uses bounded maps; **D/T:** no surviving new issue. |
| `userspace-dp/src/afxdp/session_glue/promote.rs` | negative | **C/S:** peer-synced promotion/purge predicates and shared-map publication checked; **M:** grouped shared references are immutable handles and table mutation is serialized; **V:** active-owner promotion semantics reviewed; **P:** map operations bounded; **D/T:** transient/promote tests cover translated keys. |
| `userspace-dp/src/afxdp/session_glue/tests.rs` | negative | **C/S:** 5,748-line suite covers scope lookup, translated aliases, RG indexes, demote/refresh/export, poison recovery, NAT displacement, caps, and deltas; **M:** queue/table ownership cases exercised; **V:** active/standby/split-RG behavior broad; **P:** ring-cap and epoch invalidation covered; **D/T:** no new session-glue root survived. |

### A1-b4: Rust dataplane packet path and memory safety (77 files)

Batch-list SHA-256: `e428b7914ed9b5ec07949f6c20bc69687bf32420bbcecb7b7b8d72adf7eaf5b5`.

Every ledger row was reviewed across these dimensions: **CS** correctness, security, and fail-closed behavior; **MC** memory safety, concurrency, truncation, ownership, and leaks; **VP** vSRX/Junos feature parity where applicable; **HP** packet-path allocation, locking, scan bounds, atomics, and cache effects; **MT** modularity and test adequacy. `Negative` means no credible, non-duplicate finding survived for that file, followed by the concrete invariant checked.

### TX classification and dispatch

Module sweep: CS covered egress filters, queue selection, NAT/rewrite ordering, terminal actions, segmentation, and enqueue failures. MC covered descriptor/frame ownership, cross-binding recycling, partial ring writes, and bounds. VP covered output-filter and CoS behavior. HP covered allocation-free batching and bounded queue work. MT covered production/test split and negative-path pins.

<!-- ledger-start -->
| # | Path | Module | Result | Dimensions | Concrete invariant checked |
|---:|---|---|---|---|---|
| 1 | `userspace-dp/src/afxdp/tx/cos_classify.rs` | TX CoS/filter classification | `A1-b4-F001` | CS/MC/VP/HP/MT | A flowless key must avoid fabricated ports without bypassing L3/per-packet egress output-filter terms; the early return violates that invariant. |
| 2 | `userspace-dp/src/afxdp/tx/cos_classify_tests.rs` | TX classification tests | `A1-b4-F001` | CS/MC/VP/HP/MT | Flowless BA/default queue behavior is pinned, but no test requires `is-fragment`, address/protocol, or unconditional terminal output terms to run with `flow_key=None`. |
| 3 | `userspace-dp/src/afxdp/tx/dispatch/cos.rs` | CoS enqueue dispatch | Negative | CS/MC/VP/HP/MT | CoS admission transfers each owned frame once and returns enqueue failures to an explicit recycle path without unbounded work. |
| 4 | `userspace-dp/src/afxdp/tx/dispatch/mod.rs` | TX dispatch coordinator | Negative | CS/MC/VP/HP/MT | Every forwarding/rewrite/segmentation disposition either submits, queues, or recycles the descriptor; length and fragment gates precede mutation. |
| 5 | `userspace-dp/src/afxdp/tx/dispatch/shared_recycle.rs` | Shared-UMEM recycle | Negative | CS/MC/VP/HP/MT | Cross-binding frames are returned by original fill-slot ownership, with no double recycle or silent local-pool substitution on production callers. |
| 6 | `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` | Slow-path TX rewrite | Negative | CS/MC/VP/HP/MT | Owned copies are bounds-checked before NAT/checksum rewriting and all failure exits preserve a single recycle owner. |
| 7 | `userspace-dp/src/afxdp/tx/dispatch/tests/cos_shared_exact.rs` | CoS shared-exact tests | Negative | CS/MC/VP/HP/MT | Tests pin shared exact-rate admission and frame conservation across accept/reject outcomes. |
| 8 | `userspace-dp/src/afxdp/tx/dispatch/tests/enqueue_failure.rs` | Dispatch failure tests | Negative | CS/MC/VP/HP/MT | Full rings and missing capacity fail without descriptor loss, duplicate enqueue, or unrecycled frames. |
| 9 | `userspace-dp/src/afxdp/tx/dispatch/tests/mod.rs` | Dispatch test fixtures | Negative | CS/MC/VP/HP/MT | Fixture ownership and ring sizing model production descriptor lifetimes without hiding failure paths. |
| 10 | `userspace-dp/src/afxdp/tx/dispatch/tests/ptb.rs` | PTB dispatch tests | Negative | CS/MC/VP/HP/MT | Packet-too-big generation preserves family/MTU semantics and recycles the original on synthesis or enqueue failure. |
| 11 | `userspace-dp/src/afxdp/tx/dispatch/tests/segmentation.rs` | Segmentation dispatch tests | Negative | CS/MC/VP/HP/MT | Segment fan-out checks capacity and conserves all source/child frames across partial failure. |
| 12 | `userspace-dp/src/afxdp/tx/dispatch/tests/shared_recycle.rs` | Shared recycle tests | Negative | CS/MC/VP/HP/MT | Tests cover local, remote-slot, overflow, and enqueue-failure recycle destinations exactly once. |

### TX drain, rings, statistics, and transmission

Module sweep: CS covered scheduler phase ordering, write/finalize checks, checksum and length state, and retry tails. MC covered ring reservations, partial commits, frame conservation, and sidecar bounds. VP covered strict/low priority scheduling and DSCP rewrite. HP covered batching, single-writer sidecars, and no packet-path allocation. MT covered phase boundaries and failure tests.

| 13 | `userspace-dp/src/afxdp/tx/drain/mod.rs` | TX drain orchestration | Negative | CS/MC/VP/HP/MT | Backup, shaped, and trivial phases share a bounded budget and cannot submit or recycle one request twice. |
| 14 | `userspace-dp/src/afxdp/tx/drain/phase_backup.rs` | Backup drain phase | Negative | CS/MC/VP/HP/MT | Backup queues run only after primary service and preserve request ownership when the TX ring is full. |
| 15 | `userspace-dp/src/afxdp/tx/drain/phase_shaped.rs` | Shaped drain phase | Negative | CS/MC/VP/HP/MT | Shaper credit, lease, and queue eligibility are checked before dequeue, with bounded service and explicit unsent tails. |
| 16 | `userspace-dp/src/afxdp/tx/drain/phase_trivial.rs` | Trivial drain phase | Negative | CS/MC/VP/HP/MT | Unshaped traffic uses the common submit/recycle contract and cannot bypass ring-capacity accounting. |
| 17 | `userspace-dp/src/afxdp/tx/drain/tests.rs` | Drain tests | Negative | CS/MC/VP/HP/MT | Tests pin phase precedence, budget exhaustion, full-ring retention, and exact frame/request accounting. |
| 18 | `userspace-dp/src/afxdp/tx/mod.rs` | TX module boundary | Negative | CS/MC/VP/HP/MT | Re-exports and call boundaries preserve one implementation for classify, drain, submit, and recycle operations. |
| 19 | `userspace-dp/src/afxdp/tx/rings.rs` | AF_XDP fill/completion rings | Negative | CS/MC/VP/HP/MT | Completion offsets are validated and batched; partial fill reservations retain the uninserted tail without underflow or loss. |
| 20 | `userspace-dp/src/afxdp/tx/stats.rs` | TX latency telemetry | Negative (duplicate suppressed) | CS/MC/VP/HP/MT | Sidecar indexing is bounds-safe and completion slots reset once; the shared-UMEM out-of-range sample gap is the already-reviewed `#812` root cause. |
| 21 | `userspace-dp/src/afxdp/tx/tcp_segmentation.rs` | TCP segmentation | Negative | CS/MC/VP/HP/MT | Header/payload arithmetic is checked, segment counts are bounded by frame supply, and checksum/sequence updates use the correct byte order. |
| 22 | `userspace-dp/src/afxdp/tx/test_support.rs` | TX test support | Negative | CS/MC/VP/HP/MT | Test-only builders make ownership and ring capacity explicit and do not alter production behavior. |
| 23 | `userspace-dp/src/afxdp/tx/transmit/finalise.rs` | TX finalize | Negative | CS/MC/VP/HP/MT | Only successfully prepared descriptors enter the committed prefix; retry and recycle tails remain distinguishable. |
| 24 | `userspace-dp/src/afxdp/tx/transmit/mod.rs` | TX transmit pipeline | Negative | CS/MC/VP/HP/MT | Production callers provide shared recycle routing for cross-slot frames; stage/write/finalize preserve exact ownership. |
| 25 | `userspace-dp/src/afxdp/tx/transmit/rewrite.rs` | Egress rewrite | Negative | CS/MC/VP/HP/MT | VLAN/MAC/DSCP rewrites validate offsets and lengths before mutation and repair checksums where required. |
| 26 | `userspace-dp/src/afxdp/tx/transmit/stage.rs` | TX staging | Negative | CS/MC/VP/HP/MT | Staging is capacity-bounded, retains failed requests, and performs no per-packet heap allocation. |
| 27 | `userspace-dp/src/afxdp/tx/transmit/verify.rs` | TX verification | Negative | CS/MC/VP/HP/MT | Descriptor address/length/frame boundaries fail closed before unsafe UMEM access or ring publication. |
| 28 | `userspace-dp/src/afxdp/tx/transmit/write.rs` | TX ring write | Negative | CS/MC/VP/HP/MT | Inserted-prefix counts match the ring writer result, and only committed offsets are stamped/outstanding. |
| 29 | `userspace-dp/src/afxdp/tx/transmit_tests.rs` | Transmit tests | Negative | CS/MC/VP/HP/MT | Tests exercise short frames, rewrite failures, partial writes, shared recycling, and post-commit stamping. |

### Dataplane types and shared CoS leases

Module sweep: CS covered forwarding/queue state and lease epoch math. MC covered atomics, seqlock snapshots, wrapping/narrowing, poison scenarios, and shared-map lifetime. VP covered scheduler/forwarding metadata completeness. HP covered cache-line layout, lock-free reads, and bounded maps. MT covered type ownership and epoch/lease tests.

| 30 | `userspace-dp/src/afxdp/types/cos.rs` | CoS runtime types | Negative | CS/MC/VP/HP/MT | Queue/shaper counters, packet ownership fields, and fixed-size hot state preserve rate/priority semantics without hidden allocation. |
| 31 | `userspace-dp/src/afxdp/types/cos_sojourn_tests.rs` | CoS sojourn tests | Negative | CS/MC/VP/HP/MT | Sojourn timestamps handle zero, saturation, and monotonic ordering without negative/wrapped latency. |
| 32 | `userspace-dp/src/afxdp/types/forwarding.rs` | Forwarding state types | Negative | CS/MC/VP/HP/MT | Resolution, tunnel, filter, and zone metadata have explicit defaults; malformed partial state does not fabricate a forwarding target. |
| 33 | `userspace-dp/src/afxdp/types/mod.rs` | Shared type/index root | Negative | CS/MC/VP/HP/MT | Owner-RG index poison was traced; its clear can leave stale acceleration keys, but no credible normal unwind source or policy-bearing authoritative value survived review. |
| 34 | `userspace-dp/src/afxdp/types/runtime.rs` | Worker runtime contexts | Negative | CS/MC/VP/HP/MT | Borrowed worker contexts keep UMEM, forwarding snapshots, counters, and scratch ownership scoped to the owner thread. |
| 35 | `userspace-dp/src/afxdp/types/shared_cos_lease/backlog.rs` | Shared CoS backlog | Negative | CS/MC/VP/HP/MT | Exact backlog updates saturate safely and preserve participating/non-participating queue semantics. |
| 36 | `userspace-dp/src/afxdp/types/shared_cos_lease/epoch.rs` | Lease epoch state | Negative | CS/MC/VP/HP/MT | Epoch publication uses coherent sequence checks and bounded wrap handling; readers reject torn snapshots. |
| 37 | `userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs` | Queue/root leases | Negative | CS/MC/VP/HP/MT | Acquire/release transitions are atomic, owner-qualified, and cannot spend the same credit twice. |
| 38 | `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs` | Shared lease module | Negative | CS/MC/VP/HP/MT | Module constants/layout and APIs keep one source of truth for lease, epoch, backlog, and virtual-time contracts. |
| 39 | `userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs` | Equal-flow epoch publish | Negative | CS/MC/VP/HP/MT | Publication computes a complete epoch before release, with saturating arithmetic and no reader-visible partial state. |
| 40 | `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs` | Equal-flow epoch rotation | Negative | CS/MC/VP/HP/MT | Rotation carries bounded credit/deficit and maintains monotonic generation ownership across concurrent readers. |
| 41 | `userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs` | Shared lease tests | Negative | CS/MC/VP/HP/MT | Tests cover contention, stale owners, sequence wrap, exact backlog, carry, and fail/retry paths. |
| 42 | `userspace-dp/src/afxdp/types/shared_cos_lease/vtime.rs` | Shared virtual time | Negative | CS/MC/VP/HP/MT | Fixed-point virtual-time conversions use checked/saturating math and maintain monotonic floors. |
| 43 | `userspace-dp/src/afxdp/types/tx.rs` | TX request types | Negative | CS/MC/VP/HP/MT | Request variants encode live/owned frame state, resolved CoS state, and recycle destination without ambiguous ownership. |

### UMEM and profiling

Module sweep: CS covered frame admission, inbox overflow, mmap setup, snapshots, and latency counters. MC covered unsafe slice bounds, MPSC single-consumer rules, mmap/munmap, atomics, poison, and truncation. VP was not feature-bearing beyond dataplane status parity. HP covered fixed-capacity queues, cache-aligned owner writes, and bounded snapshots. MT covered split debug/profile/mmap modules and deterministic tests.

| 44 | `userspace-dp/src/afxdp/umem/debug_state.rs` | UMEM debug state | Negative | CS/MC/VP/HP/MT | Debug snapshots read bounded owner state without exposing mutable UMEM aliases or changing hot-path ownership. |
| 45 | `userspace-dp/src/afxdp/umem/mmap.rs` | UMEM mmap owner | Negative | CS/MC/VP/HP/MT | Length alignment is checked, MAP_FAILED is handled, slice arithmetic is bounded, and Drop unmaps the actual mapped length; null-success leak was not reachable on the target Linux mapping policy. |
| 46 | `userspace-dp/src/afxdp/umem/mmap_tests.rs` | mmap hardening tests | Negative | CS/MC/VP/HP/MT | Tests pin zero/overflow rejection, requested-vs-mapped lengths, bounded slices, and drop lifetime. |
| 47 | `userspace-dp/src/afxdp/umem/mod.rs` | Binding/UMEM live state | Negative | CS/MC/VP/HP/MT | Pending-TX admission is CAS-bounded, MPSC drain has one consumer, and session-delta poison was rejected because the locked operations contain no credible unwinding production call. |
| 48 | `userspace-dp/src/afxdp/umem/profile.rs` | Owner profiling state | Negative | CS/MC/VP/HP/MT | Single-writer/cache-line layout and relaxed telemetry atomics do not carry forwarding correctness or create mutable aliases. |
| 49 | `userspace-dp/src/afxdp/umem/snapshot.rs` | UMEM snapshots | Negative | CS/MC/VP/HP/MT | Snapshot projection is bounded and owned; relaxed multi-field skew is telemetry-only and documented. |
| 50 | `userspace-dp/src/afxdp/umem/tests/debug_state.rs` | Debug-state tests | Negative | CS/MC/VP/HP/MT | Tests pin state projection and reset behavior without relying on mutable shared borrows. |
| 51 | `userspace-dp/src/afxdp/umem/tests/latency_buckets.rs` | Latency bucket tests | Negative | CS/MC/VP/HP/MT | Bucket boundaries, saturation, and extreme durations cannot index outside fixed histograms. |
| 52 | `userspace-dp/src/afxdp/umem/tests/mmap_area.rs` | mmap-area tests | Negative | CS/MC/VP/HP/MT | Mutable/immutable slice boundaries reject overflow and out-of-range regions. |
| 53 | `userspace-dp/src/afxdp/umem/tests/mod.rs` | UMEM test root | Negative | CS/MC/VP/HP/MT | Test module wiring includes debug, mmap, snapshot, inbox, and both latency surfaces. |
| 54 | `userspace-dp/src/afxdp/umem/tests/snapshot_propagation.rs` | Snapshot propagation tests | Negative | CS/MC/VP/HP/MT | Owner counters and histograms reach status snapshots with stable lengths/defaults. |
| 55 | `userspace-dp/src/afxdp/umem/tests/tx_inbox.rs` | Redirect inbox tests | Negative | CS/MC/VP/HP/MT | Capacity, overflow accounting, FIFO drain, and admission release preserve one slot per queued request. |
| 56 | `userspace-dp/src/afxdp/umem/tests/tx_kick_latency.rs` | Kick-latency tests | Negative | CS/MC/VP/HP/MT | Histogram/count/sum updates handle boundaries and retain bounded telemetry skew. |
| 57 | `userspace-dp/src/afxdp/umem/tests/tx_submit_latency.rs` | Submit-latency tests | Negative (duplicate suppressed) | CS/MC/VP/HP/MT | Post-commit stamps, sentinel reset, retry tails, and shared-UMEM OOB safety are pinned; the OOB observability limitation is already tracked under `#812`. |

### WireGuard

Module sweep: CS covered cryptokey routing, framing lengths/endian, MAC/cookie/Noise handshakes, replay, AllowedIPs, timers, rekey slots, and fail-closed parse paths. MC covered output wiping, stack staging, lock ordering, ArcSwap snapshots, counters, and buffer bounds. VP covered practical WireGuard tunnel semantics rather than Junos policy parity. HP covered allocation-free transport hot paths and bounded lookup/replay work. MT covered split protocol modules and extensive negative/concurrency tests.

| 58 | `userspace-dp/src/afxdp/wg/allowed_ips.rs` | AllowedIPs LPM | Negative | CS/MC/VP/HP/MT | IPv4/IPv6 longest-prefix lookup is bounded by address width and returns the owning peer index deterministically. |
| 59 | `userspace-dp/src/afxdp/wg/cookie.rs` | WG cookie defense | Negative | CS/MC/VP/HP/MT | MAC/cookie key derivation, nonce sizing, expiry, and source binding reject malformed or stale material. |
| 60 | `userspace-dp/src/afxdp/wg/cookie_tests.rs` | Cookie tests | Negative | CS/MC/VP/HP/MT | Known vectors and malformed length/source/expiry cases cover both generation and consumption. |
| 61 | `userspace-dp/src/afxdp/wg/counters.rs` | WG telemetry | Negative | CS/MC/VP/HP/MT | Relaxed counters are diagnostic-only, overflow-tolerant, and do not control packet acceptance. |
| 62 | `userspace-dp/src/afxdp/wg/dscp.rs` | WG DSCP mapping | Negative | CS/MC/VP/HP/MT | DSCP is masked into the outer TOS field with ECN behavior explicit and no narrowing ambiguity. |
| 63 | `userspace-dp/src/afxdp/wg/engine.rs` | WG peer/session engine | Negative | CS/MC/VP/HP/MT | Encap/decap lengths, replay, AllowedIPs, keypair rotation, and snapshot publication were traced; duplicate pubkeys are rejected by the only production config constructor. |
| 64 | `userspace-dp/src/afxdp/wg/engine_tests.rs` | Engine unit tests | Negative | CS/MC/VP/HP/MT | Tests cover session install/remove, reconciliation, replay, expiry, concurrent snapshots, and malformed transport records. |
| 65 | `userspace-dp/src/afxdp/wg/framing.rs` | WG data framing | Negative | CS/MC/VP/HP/MT | Type/index/counter fields use WireGuard little-endian layout and reject short/incorrect message forms before slicing. |
| 66 | `userspace-dp/src/afxdp/wg/handshake.rs` | WG handshake framing | Negative | CS/MC/VP/HP/MT | Fixed message lengths, MAC1/MAC2 offsets, and cookie fields are bounds-checked before cryptographic processing. |
| 67 | `userspace-dp/src/afxdp/wg/handshake_session.rs` | WG handshake lifecycle | Negative | CS/MC/VP/HP/MT | Pending reservations are peer/index-qualified, failures preserve valid reservations where required, and completion installs one role-correct session. |
| 68 | `userspace-dp/src/afxdp/wg/handshake_tests.rs` | Handshake tests | Negative | CS/MC/VP/HP/MT | Tests pin wire vectors, MAC failures, unknown peers, tampering, PSKs, and reservation cleanup. |
| 69 | `userspace-dp/src/afxdp/wg/mod.rs` | WG module/API | Negative | CS/MC/VP/HP/MT | Protocol constants and re-exports keep one wire contract and redact/zeroize secret-bearing types. |
| 70 | `userspace-dp/src/afxdp/wg/mss.rs` | WG MSS calculation | Negative | CS/MC/VP/HP/MT | Family-specific outer overhead, AEAD framing, and worst-case padding are subtracted with bounded arithmetic. |
| 71 | `userspace-dp/src/afxdp/wg/peer.rs` | WG peer state | Negative | CS/MC/VP/HP/MT | Current/previous/next session locks preserve confirmed-egress and responder-promotion ordering; timer atomics are monotonic. |
| 72 | `userspace-dp/src/afxdp/wg/scratch.rs` | WG worker scratch | Negative | CS/MC/VP/HP/MT | Per-worker buffers are preallocated and interior borrows remain thread-local; no packet-path heap growth is required. |
| 73 | `userspace-dp/src/afxdp/wg/session.rs` | WG transport session | Negative | CS/MC/VP/HP/MT | TX counter reservation stops before the spec ceiling and the 64-packet replay window rejects repeats/out-of-window counters without wrap. |
| 74 | `userspace-dp/src/afxdp/wg/tai64n.rs` | TAI64N clock | Negative | CS/MC/VP/HP/MT | Monotonic generation handles nanosecond carry and produces strictly increasing 12-byte network-order timestamps. |
| 75 | `userspace-dp/src/afxdp/wg/tai64n_tests.rs` | TAI64N tests | Negative | CS/MC/VP/HP/MT | Tests cover carry, rollback, high-water seeding, encoding, and ordering boundaries. |
| 76 | `userspace-dp/src/afxdp/wg/tests.rs` | WG end-to-end tests | Negative | CS/MC/VP/HP/MT | End-to-end coverage includes framing, cryptokey routing, replay, wipe-on-error, truncation, rekey slots, concurrency, telemetry, and timer semantics. |
| 77 | `userspace-dp/src/afxdp/wg/timers.rs` | WG timers | Negative | CS/MC/VP/HP/MT | T1/T2/T3/T5/T6/T7/T8 deadlines are saturating, role-aware, endpoint-gated, and return bounded actions rather than loops. |
<!-- ledger-end -->

### A1-b5: Rust dataplane packet path and memory safety (75 files)

Batch-list SHA-256: `a401f57883ed47ff41fd09af5ae8df61e4d6cb106c4b20905cf8218d563117a3`.

### AF_XDP worker and CoS

Dimensions applied: correctness/security and fail-closed behavior were traced through binding setup, state rotation, session-delta flushing, TX ownership, and XSK ring teardown; memory/concurrency/truncation/leak review covered ArcSwap guards, atomics, queue/recycle ownership, FD lifetimes, casts, and saturating timer math; vSRX parity was checked for CoS/status and HA fabric behavior; packet-path performance covered allocation, cloning, locks, scans, and cache-line traffic; modularity and tests were checked against the split worker modules and the CoS regression suite. Findings survive in the packet-loop orchestration; no additional memory-safety defect survived.

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 001 | `userspace-dp/src/afxdp/worker/bind_meta.rs` | Worker binding metadata | negative | Binding identity and metadata projection preserve widths and do not acquire frame/FD ownership. |
| 002 | `userspace-dp/src/afxdp/worker/bpf_maps.rs` | Worker BPF-map handles | negative | Map descriptors remain borrowed worker state; no hidden close, alias, narrowing, or stale-map mutation was found. |
| 003 | `userspace-dp/src/afxdp/worker/cos/interface_row.rs` | CoS interface telemetry | negative | Per-interface counters use saturating/delta-safe projection and do not mutate scheduler state while reporting. |
| 004 | `userspace-dp/src/afxdp/worker/cos/mod.rs` | CoS worker aggregation | negative | Owner-profile merge, queue accounting, and atomics preserve sum/max semantics without packet-path allocation. |
| 005 | `userspace-dp/src/afxdp/worker/cos/queue_row.rs` | CoS queue telemetry | negative | Queue-depth, byte, vtime, and drop fields retain integer widths and consistent local/shared ownership. |
| 006 | `userspace-dp/src/afxdp/worker/cos/status.rs` | CoS status publication | negative | Snapshot publication is read-only, bounded by configured queues, and coherent with worker-local counters. |
| 007 | `userspace-dp/src/afxdp/worker/cos/tests.rs` | CoS tests | negative | Tests cover merges, exact/shared queue ownership, counter resets, and overflow edges; no untested defect survived this batch. |
| 008 | `userspace-dp/src/afxdp/worker/cos_state.rs` | Worker CoS state | negative | Arc-backed owner/lease maps rotate without mutable aliasing and preserve cached runtime ownership. |
| 009 | `userspace-dp/src/afxdp/worker/flow_cache_state.rs` | Flow-cache state | negative | Generation/cached-state replacement invalidates stale decisions without sharing mutable packet state. |
| 010 | `userspace-dp/src/afxdp/worker/lifecycle.rs` | Worker lifecycle | negative | Bind failure, cancellation, joins, UMEM/XSK destruction, and retry paths release resources in a bounded order. |
| 011 | `userspace-dp/src/afxdp/worker/loop_body/debug_report.rs` | Worker debug reporting | negative | Debug-only aggregation is cadence-gated and does not introduce production per-packet formatting or unbounded state. |
| 012 | `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | Packet-worker loop | `A1-b5-F001`, `A1-b5-F003` | The loop must never block on control/telemetry and cached forwarding state must converge to one published generation. Both invariants fail. |
| 013 | `userspace-dp/src/afxdp/worker/loop_body/setup.rs` | Worker setup | negative | Ring/UMEM setup establishes one owner for each queue and fails closed on partial binding initialization. |
| 014 | `userspace-dp/src/afxdp/worker/mod.rs` | Worker types/helpers | negative | Hashing, ArcSwap change detection, worker structs, and frame ownership helpers do not narrow lengths or duplicate ownership. |
| 015 | `userspace-dp/src/afxdp/worker/scratch.rs` | Reusable worker scratch | negative | Scratch vectors are worker-owned and capacity-reused; no cross-thread alias, leak, or unbounded packet-driven growth survived. |
| 016 | `userspace-dp/src/afxdp/worker/telemetry.rs` | Worker telemetry | negative | Relaxed atomic telemetry is observational only and cannot control forwarding or corrupt ownership. |
| 017 | `userspace-dp/src/afxdp/worker/timers.rs` | Worker timers | negative | Monotonic, saturating deadline math avoids wall-clock and underflow errors. |
| 018 | `userspace-dp/src/afxdp/worker/tx_counters.rs` | TX counters | negative | TX disposition/drop counters are non-owning and cannot perturb queue/recycle decisions. |
| 019 | `userspace-dp/src/afxdp/worker/tx_pipeline.rs` | TX pipeline state | negative | Pending and in-flight collections retain a single recycle disposition per descriptor; no loss/double-recycle path survived. |
| 020 | `userspace-dp/src/afxdp/worker/xsk_rings.rs` | XSK rings | negative | Ring producer/consumer pointers remain tied to the owning socket and lifecycle; no unsafe alias or teardown leak was found. |

### Event stream and RT_FLOW codec

Dimensions applied: correctness/security covered sequence continuity, fail-closed session-sync recovery, frame lengths, address families, partial control frames, and replay/drain semantics; memory/concurrency/truncation/leak review covered bounded channels/buffers, mutex scope, atomics, partial writes, fixed 256-byte frames, and sender teardown; vSRX parity covered RT_FLOW address rendering and HA session fields; performance covered producer blocking, writer backpressure, allocation, and retry cadence; modularity/tests covered codec separation and all assigned producer, backpressure, control, drain, replay, and RT_FLOW tests. Two production findings remain.

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 021 | `userspace-dp/src/event_stream/codec/codec_tests.rs` | Codec tests | `A1-b5-F002` | Wire-layout tests cover pure IPv4/IPv6 and NAT64 session-sync, but never assert mixed-family NAT fields in RT_FLOW create/close frames. |
| 022 | `userspace-dp/src/event_stream/codec/decode.rs` | Control-frame decode | negative | Length/type checks reject partial or unknown control payloads before indexed reads. |
| 023 | `userspace-dp/src/event_stream/codec/mod.rs` | Codec module boundary | negative | Re-exports preserve one frame definition and keep session-sync and RT_FLOW encoders distinct. |
| 024 | `userspace-dp/src/event_stream/codec/rt_flow.rs` | RT_FLOW encode | `A1-b5-F002` | A single original address-family byte is incorrectly reused for cross-family NAT address slots. |
| 025 | `userspace-dp/src/event_stream/codec/session_sync.rs` | HA session-sync encode | negative | NAT64 is separately tagged and carries `snat_v4`; fixed-slot writes and optional tails remain length-bounded. |
| 026 | `userspace-dp/src/event_stream/codec/wire.rs` | Wire constants/helpers | `A1-b5-F002` | `write_ip_16` left-aligns IPv4 in a 16-byte slot while `rt_flow_addr_family` remains IPv6 for a NAT64 original tuple. |
| 027 | `userspace-dp/src/event_stream/mod.rs` | Event-stream orchestration | `A1-b5-F001`, `A1-b5-F002` | Packet workers must not sleep on an open slow consumer; RT_FLOW must encode original and translated families unambiguously. Both fail. |
| 028 | `userspace-dp/src/event_stream/producer.rs` | Event producer/rate budget | negative | Per-kind/zone budgets, queue reservation, and sequence rollback avoid monopolization and lossy sequence holes. |
| 029 | `userspace-dp/src/event_stream/producer_tests.rs` | Producer tests | negative | Tests cover queue full/disconnect, per-kind budgets, and sequence rollback; no additional producer defect survived. |
| 030 | `userspace-dp/src/event_stream/tests/backpressure.rs` | Backpressure tests | `A1-b5-F001` | Tests explicitly establish that a full lossless send waits, but do not place that wait in a packet-worker heartbeat/forwarding harness. |
| 031 | `userspace-dp/src/event_stream/tests/control_frames.rs` | Control-frame tests | negative | Partial, coalesced, unknown, ACK, pause, and resume frames retain bytes until complete and reject invalid watermarks. |
| 032 | `userspace-dp/src/event_stream/tests/drain.rs` | Drain tests | negative | Drain deadlines, poison, pause restoration, and completion fencing remain bounded and fail closed. |
| 033 | `userspace-dp/src/event_stream/tests/mod.rs` | Event test fixtures | negative | Shared fixtures preserve channel and session metadata contracts without hiding production ownership. |
| 034 | `userspace-dp/src/event_stream/tests/replay_budget.rs` | Replay tests | negative | Replay eviction is bounded, session loss poisons recovery, and telemetry eviction does not spuriously resync. |
| 035 | `userspace-dp/src/event_stream/tests/rt_flow.rs` | RT_FLOW producer tests | `A1-b5-F002` | Producer gates and fields are covered for same-family tuples; NAT64 create/close consumer rendering is absent. |

### Fairness evaluator

Dimensions applied: correctness/security covered strict CLI/input parsing, steady-state windows, connected-stream denominators, and verdict thresholds; memory/concurrency/truncation/leak review covered bounded offline collections and integer/floating conversions (no unsafe or live shared state); vSRX parity is not applicable to this offline evaluator; performance covered linear grouping/sorting on operator-supplied artifacts rather than packet-path work; modularity/tests covered argument, input, per-worker, RSS, window, report, and verdict boundaries. No finding survived.

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 036 | `userspace-dp/src/bin/fairness-eval.rs` | CLI entrypoint | negative | Errors propagate to a non-zero exit and no partial PASS report is emitted. |
| 037 | `userspace-dp/src/fairness_eval/args.rs` | CLI parsing | negative | Required paths, thresholds, queue IDs, durations, and numeric bounds reject malformed values. |
| 038 | `userspace-dp/src/fairness_eval/inputs.rs` | JSON/TSV inputs | negative | Schema, row width, numeric parsing, and interface filtering reject malformed evidence instead of inventing samples. |
| 039 | `userspace-dp/src/fairness_eval/mod.rs` | Evaluation orchestration | negative | Empty/missing evidence flows into explicit zero/failure verdict inputs rather than a false PASS. |
| 040 | `userspace-dp/src/fairness_eval/per_worker.rs` | Worker aggregation | negative | Binding rows aggregate by worker/timestamp before median calculation and retain expected zero-flow workers. |
| 041 | `userspace-dp/src/fairness_eval/per_worker_tests.rs` | Worker aggregation tests | negative | Multi-binding, missing-worker, median, and skew cases pin the intended denominator and aggregation. |
| 042 | `userspace-dp/src/fairness_eval/report.rs` | Report schema | negative | Serialized evidence names inputs/thresholds and does not truncate counters or silently omit failed checks. |
| 043 | `userspace-dp/src/fairness_eval/rss.rs` | RSS expectation | negative | CPU/queue sets are parsed and compared deterministically with duplicate suppression. |
| 044 | `userspace-dp/src/fairness_eval/verdict.rs` | Verdict logic | negative | Threshold comparisons handle zero denominators and NaN-adjacent cases without fail-open PASS. |
| 045 | `userspace-dp/src/fairness_eval/windowing.rs` | Steady-state windows | negative | Timestamp/window bounds and bucket aggregation avoid underflow, overlap ambiguity, and empty-window success. |

### Firewall filter compiler and engine

Dimensions applied: correctness/security covered family qualification, term order, malformed/missing references, fragment/L4 matching, terminal actions, logging, counters, and policer fail-closed behavior; memory/concurrency/truncation/leak review covered immutable compiled state, Arc-backed policers, atomics, token arithmetic, and cache replay; vSRX parity covered input/output/lo0 matching and policer/color semantics; performance covered cache-sensitive gates, precomputed flags, bounded term scans, and no hot-path allocation; modularity/tests covered compiler/engine/policer separation and the assigned regression corpus. The missing-reference observation was suppressed as `#2217`; no novel finding remains.

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 046 | `userspace-dp/src/filter/compiler.rs` | Filter compiler | negative | Snapshot integrity, family-qualified names, stable policer IDs, and derived fast-path gates fail closed; missing-policer concern is duplicate `#2217`. |
| 047 | `userspace-dp/src/filter/engine/cache_sensitive.rs` | Flow-cache sensitivity | negative | DSCP/L4/policer-sensitive terms decline unsafe caching and replay only sufficient immutable decision data. |
| 048 | `userspace-dp/src/filter/engine/eval.rs` | Filter evaluation | negative | Ordered first-match, terminal/default behavior, counters, logs, and family/interface dispatch preserve fail-closed semantics. |
| 049 | `userspace-dp/src/filter/engine/matching.rs` | Term matching | negative | Prefix, port, protocol, TCP flag, fragment, ICMP, DSCP, and exclusion predicates do not match absent L4 fields. |
| 050 | `userspace-dp/src/filter/engine/mod.rs` | Engine module boundary | negative | Public(crate) exports keep counted, logged, non-routing, and TX-selection paths on shared primitives. |
| 051 | `userspace-dp/src/filter/engine/policer.rs` | Runtime policer application | negative | Missing runtime handles fail closed and cached replay cannot bypass a configured meter. |
| 052 | `userspace-dp/src/filter/engine/tx_selection.rs` | Filter TX selection | negative | Forwarding-class/DSCP/routing-instance selection preserves terminal actions and counted/logged evaluation requirements. |
| 053 | `userspace-dp/src/filter/mod.rs` | Compiled filter state | negative | Arc/atomic caches, counters, handles, and generation-sensitive flags avoid mutable packet-path aliasing and ID truncation. |
| 054 | `userspace-dp/src/filter/policer.rs` | Token/color policers | negative | Refill and burst arithmetic saturate, invalid configurations fail closed, and concurrent tokens/counters use coherent atomics. |
| 055 | `userspace-dp/src/filter/tests.rs` | Filter tests | negative | Broad family/action/cache/policer/log/counter regression coverage was inspected; no new defect beyond the suppressed reference class survived. |

### Control protocol snapshots

Dimensions applied: correctness/security covered serde defaults, enum/tag compatibility, signed/unsigned widths, snapshots, policy/screen/NAT/CoS fields, and malformed input behavior; memory/concurrency/truncation/leak review found pure owned decode types with bounded numeric fields and no unsafe/shared mutable state; vSRX parity covered configuration expressiveness carried to Rust; performance covered decode-time allocation only, outside packet processing; modularity/tests covered split protocol domains and round trips. No finding survived.

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 056 | `userspace-dp/src/protocol/binding.rs` | Binding protocol | negative | Interface, queue, UMEM, RSS, and binding-plan fields retain signedness/width and backward-compatible defaults. |
| 057 | `userspace-dp/src/protocol/control.rs` | Control messages | negative | Tagged request/response variants and optional payloads cannot silently reinterpret one operation as another. |
| 058 | `userspace-dp/src/protocol/cos.rs` | CoS protocol | negative | Scheduler, queue, classifier, rewrite, rate, and burst fields retain units and widths across serde. |
| 059 | `userspace-dp/src/protocol/mod.rs` | Protocol module boundary | negative | Re-exports preserve one canonical schema for server/coordinator consumers. |
| 060 | `userspace-dp/src/protocol/nat.rs` | NAT protocol | negative | NAT, NAT64, NPTv6, ports, prefixes, and cross-family address strings remain explicitly typed and defaulted. |
| 061 | `userspace-dp/src/protocol/resolution.rs` | Resolution protocol | negative | Disposition and resolution fields retain tunnel/fabric/egress distinctions and do not narrow interface IDs. |
| 062 | `userspace-dp/src/protocol/security.rs` | Security protocol | negative | Policy, application, screen, ALG, timeout, and SYN-cookie fields carry explicit defaults without fail-open variant collapse. |
| 063 | `userspace-dp/src/protocol/snapshot.rs` | Aggregate snapshot | negative | Top-level generations and domain vectors remain transactional inputs; optional old-peer fields default compatibly. |
| 064 | `userspace-dp/src/protocol/tests.rs` | Protocol tests | negative | Round trips, defaults, large IDs, optional fields, and schema evolution are covered; no width/default drift survived. |

### Screen engine

Dimensions applied: correctness/security covered fail-closed extraction, stateless signatures, flood/SYN rates, scan/sweep tracking, SYN-cookie validation, and profile changes; memory/concurrency/truncation/leak review covered fixed-size sketches/tables, expiry, wrapping epochs, crypto comparisons, parser bounds, and worker-local mutability; vSRX parity covered malformed options, flood, scan, sweep, LAND/teardrop, and cookie behavior; performance covered allocation-free extraction, bounded scans, cleanup cadence, and per-zone memory; modularity/tests covered extractor/rate/scan/stateless/syncookie splits and assigned tests. The profile-state observation was conservatively suppressed as the same root-cause class as `#2446`; the IHL concern was refuted by the sole steering path.

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 065 | `userspace-dp/src/screen/extract.rs` | Packet extraction | negative | Bounds and malformed options fail closed; apparent IHL less-than-five omission is unreachable because userspace-XDP rejects `ihl < 20` before redirect. |
| 066 | `userspace-dp/src/screen/mod.rs` | Screen orchestration/state | negative | Profile/state lifecycle, flowless checks, flood gates, and cookie ACK handling were traced; retained active-window concern is suppressed as duplicate `#2446`. |
| 067 | `userspace-dp/src/screen/packet.rs` | Screen packet model | negative | Parsed widths/defaults distinguish absent L4 data and carry fragment/length state without ownership. |
| 068 | `userspace-dp/src/screen/rate.rs` | Rate tables | negative | Fixed-capacity buckets, expiry, hashing, and saturating counters bound attacker-driven memory and arithmetic. |
| 069 | `userspace-dp/src/screen/rate_tests.rs` | Rate tests | negative | Collision, expiry, thresholds, and capacity behavior pin bounded fail-closed rate accounting. |
| 070 | `userspace-dp/src/screen/scan.rs` | Port-scan/IP-sweep | negative | Source/destination tracking, pressure events, eviction, and cleanup are capacity/cadence bounded. |
| 071 | `userspace-dp/src/screen/stateless.rs` | Stateless signatures | negative | LAND, teardrop, fragments, TCP flags, ICMP, source-route, and malformed header decisions use explicit drop predicates. |
| 072 | `userspace-dp/src/screen/syn_rate.rs` | SYN-rate sketches | negative | Fixed sketches, hash lanes, epoch reset, and threshold math avoid unbounded per-source allocation and counter wrap bypass. |
| 073 | `userspace-dp/src/screen/syn_rate_tests.rs` | SYN-rate tests | negative | Source/destination thresholds, reset, collision, and saturation behavior are covered. |
| 074 | `userspace-dp/src/screen/syncookie.rs` | SYN cookies | negative | Tuple/family encoding, epoch windows, MSS bits, keyed MAC validation, and wrapping sequence arithmetic were checked. |
| 075 | `userspace-dp/src/screen/tests.rs` | Screen tests | negative | Malformed/truncated, stateless, flood, scan/sweep, profile, and cookie regression coverage was inspected; no novel survivor remains. |

### A1-b6: Rust dataplane packet path and memory safety (31 files)

Batch-list SHA-256: `c6d4467c91aa8402538ae153951f7c1fd4328817c92e3b6af920ab28d5ead09d`.

The ledger uses five explicit dimensions in every row: C/S = correctness,
security, and fail-open behavior; M/C = memory safety, concurrency, truncation,
and leaks; P = vSRX parity where relevant; L = performance/latency; M/T =
modularity and test gaps. Directly called contracts were used only to confirm or
refute candidates; they are not extra coverage-ledger entries.

### Server handlers

| Path | Module/subsystem | Result | Five-dimension invariant checked |
|---|---|---|---|
| userspace-dp/src/server/handlers/binding.rs | Per-binding control | negative | C/S: registration/arming mutations stay slot-scoped; M/C: serialized by ServerState and no ownership leak; P: operational control, no parity gap; L: the settle-under-lock pattern was suppressed as the known #2962/#4054 root cause; M/T: handler boundary and unknown-slot tests were inspected. |
| userspace-dp/src/server/handlers/export.rs | Session export control | negative | C/S: export errors reach the response; M/C: wait handles outlive the lock safely; P: HA export semantics retained; L: blocking owner/all export work is split off the global lock; M/T: kick/collect ownership is explicit and covered. |
| userspace-dp/src/server/handlers/forwarding.rs | Forwarding arm/disarm | A1-b6-F001 | C/S: arm uses the stored snapshot but does not repair its earlier validation gap; M/C: no raw-memory issue; P: fail-closed arm behavior matters to routing parity; L: settle is cold-path but globally blocking (known duplicate); M/T: ignored reconcile outcome is coupled to snapshot acceptance. |
| userspace-dp/src/server/handlers/ha.rs | HA state update | negative | C/S: coordinator update plus refresh restores authoritative status; M/C: mutex serialization prevents torn HA state; P: RG state fields were traced; L: bounded update with no packet-path allocation; M/T: provisional status mutation was refuted because failed updates are not persisted and refresh replaces it. |
| userspace-dp/src/server/handlers/inject_packet.rs | Diagnostic packet injection | negative | C/S: generation and tuple validation failures are returned; M/C: packet ownership transfers through the coordinator without raw pointer use; P: diagnostic-only; L: bounded operator path; M/T: missing payload and coordinator error tests exist. |
| userspace-dp/src/server/handlers/mod.rs | Control dispatcher | A1-b6-F002 | C/S: one decoded verb is dispatched under the shared state lock; M/C: export waits are correctly off-lock, but persistence is synchronous after dispatch; P: shared HA/status/session control surface inspected; L: F002 makes delta polling a durable-write path; M/T: lock boundaries are documented but not uniformly enforced by callees. |
| userspace-dp/src/server/handlers/neighbors.rs | Manager neighbor publication | A1-b6-F006 | C/S: malformed rows are silently omitted even for authoritative replacement; M/C: bounded temporary vector and no unsafe code; P: neighbor convergence is parity-relevant; L: replacement is cold-path and bulk-published; M/T: no mixed-validity replacement regression test. |
| userspace-dp/src/server/handlers/queue.rs | Per-queue control | negative | C/S: updates are queue-scoped and unknown queues fail; M/C: serialized mutation; P: operational control only; L: settle-under-lock candidate is a #2962/#4054 duplicate; M/T: delegates reconciliation consistently with binding control. |
| userspace-dp/src/server/handlers/rebind.rs | Rebind control | negative | C/S: replan/reconcile status is refreshed; M/C: no unsafe ownership transition; P: link-cycle recovery inspected; L: cold-path bounded by configured plan; M/T: small handler keeps orchestration in helpers. |
| userspace-dp/src/server/handlers/session_deltas.rs | HA delta drain | A1-b6-F002 | C/S: ring drain result is returned; M/C: no truncation beyond requested cap; P: HA replication fallback depends on it; L: every drain, including empty drains, forces full durable state persistence; M/T: no dirty-state predicate or empty-drain negative test. |
| userspace-dp/src/server/handlers/snapshot.rs | Snapshot transaction | A1-b6-F001 | C/S: first/disarmed and defer-workers branches can acknowledge without full forwarding validation; M/C: F003 is reached during replan; P: stale/invalid apply behavior violates transactional parity; L: build/replan is cold control work; M/T: same-plan and armed failures are tested, but the uncovered branches are not. |
| userspace-dp/src/server/handlers/stop_workers.rs | Worker stop control | negative | C/S: stop is explicit and status is refreshed; M/C: coordinator owns teardown; P: maintenance-only; L: no hot-path work; M/T: narrow handler has no hidden policy decision. |
| userspace-dp/src/server/handlers/sync_session.rs | HA session import/delete | A1-b6-F004 | C/S: most malformed fields reject, while malformed NAT64 discriminator downgrades; M/C: imported values remain owned; P: reverse NAT64 after promotion is parity-critical; L: control-path allocation only; M/T: valid/legacy NAT64 cases exist but malformed non-empty input is absent. |

### Server core

| Path | Module/subsystem | Result | Five-dimension invariant checked |
|---|---|---|---|
| userspace-dp/src/server/helpers.rs | Server planning/build helpers | A1-b6-F001, A1-b6-F002, A1-b6-F003, A1-b6-F004 | C/S: snapshot, sync, and neighbor helper contracts were traced; M/C: queue cardinality is unchecked and state persistence retains the mutex across the writer wait; P: NAT64/HA and transactional apply are parity-relevant; L: F002 is shared-control-path blocking and F003 is unbounded cold work; M/T: several unrelated responsibilities remain centralized and the failing boundaries lack negative tests. |
| userspace-dp/src/server/lifecycle.rs | Listener/process lifecycle | negative | C/S: stale-socket type check and request-thread lifecycle were inspected; M/C: listener ownership and shutdown atomics are coherent; P: N/A; L: nonblocking accepts and bounded sleep are appropriate; M/T: predictable /tmp namespace candidate was suppressed as the prior attacker-owned /tmp root cause, and normal service umask blocks unprivileged connect. |
| userspace-dp/src/server/mod.rs | Server module boundary | negative | C/S: exports only the lifecycle entry point; M/C: no state or unsafe code; P: N/A; L: N/A; M/T: module split is clear. |
| userspace-dp/src/server/state.rs | Shared server state | negative | C/S: snapshot/status/coordinator remain under one authority; M/C: Arc/Mutex and writer ownership are sound, with F002 caused by lock duration rather than aliasing; P: status is the control-plane contract; L: coarse lock is sensitive to blocking callees; M/T: state shape is compact but creates broad contention. |
| userspace-dp/src/server/tests.rs | Server regression suite | A1-b6-F001, A1-b6-F004, A1-b6-F006 (missing negative cases) | C/S: integrity, arm/disarm, rebind, sync, and neighbor behavior were inspected; M/C: test seams avoid real BPF FDs; P: HA/NAT64 scenarios are represented; L: no empty high-frequency delta persistence test; M/T: first invalid disarmed/deferred apply, malformed NAT64, and mixed-validity neighbor replacement are untested. |

### Session table

| Path | Module/subsystem | Result | Five-dimension invariant checked |
|---|---|---|---|
| userspace-dp/src/session/ctx.rs | Session operation context | negative | C/S: time/generation/metadata inputs stay explicit; M/C: borrowed context has no unsafe lifetime extension; P: metadata carries HA ownership; L: compact hot-path parameter object; M/T: clean separation. |
| userspace-dp/src/session/entry.rs | Session entry/state | negative | C/S: origin, timeout, NAT and companion state were traced; M/C: atomics/owned data avoid dangling references; P: synced/local origin distinctions preserved; L: hot fields avoid per-hit allocation; M/T: state transitions are test-covered. |
| userspace-dp/src/session/expire.rs | Expiry/GC | negative | C/S: stale synced/local and companion decisions are fail-closed; M/C: removal/reindex ordering is coherent; P: owner-RG expiry behavior inspected; L: elapsed-tick catch-up matches the already tracked #1782 over-horizon wheel root cause and was suppressed; M/T: tests explicitly document the large-jump behavior. |
| userspace-dp/src/session/install.rs | Transactional install/import | negative | C/S: capacity and reverse companion rollback were traced; M/C: indexes are rolled back on failed install; P: sync imports are intentionally uncapped by the documented #1861 design; L: bounded normal install with collision indexes; M/T: collision/cap tests are extensive. |
| userspace-dp/src/session/key.rs | Tuple/reverse-key construction | negative | C/S: address-family, NAT, NAT64, NPTv6, and reverse tuple derivation inspected; M/C: value-only transformations; P: v4/v6 parity covered; L: fixed-cost hashing/construction; M/T: edge matrices exist. |
| userspace-dp/src/session/lookup.rs | Primary/reverse lookup | negative | C/S: candidate validation prevents stale-index acceptance; M/C: handle generation checks prevent reused-slot aliasing; P: translated and fabric paths inspected; L: bounded candidate vectors in normal operation; M/T: genuine identical translated-tuple ambiguity is the known #1758/#4399/#4438 root cause and was suppressed. |
| userspace-dp/src/session/mod.rs | Session table/index owner | negative | C/S: install/refresh/delete/HA promotion chains were followed; M/C: generation-stamped handles and index cleanup are coherent; P: HA demotion/promotion semantics inspected; L: sharded/indexed hot paths avoid global scans except documented maintenance; M/T: module is large but split helpers/tests pin invariants. |
| userspace-dp/src/session/tests.rs | Session regression suite | negative | C/S: NAT/NAT64, HA, collision, capacity, expiry, companion, and generation matrices inspected; M/C: index cardinality/rollback assertions are broad; P: promotion/failback coverage is substantial; L: large clock jump and collision costs are explicitly exercised; M/T: known residual owner-RG-zero and collision cases were duplicate-suppressed. |
| userspace-dp/src/session/wheel.rs | Timer wheel buckets | negative | C/S: slot/tick mapping and rebucketing are deterministic; M/C: VecDeque ownership is safe; P: N/A; L: O(1) normal insert/remove, with catch-up duplicate noted in expire.rs; M/T: simple module with direct tests. |

### Contract tests and XDP shim

| Path | Module/subsystem | Result | Five-dimension invariant checked |
|---|---|---|---|
| userspace-dp/tests/cos_doc_drift.rs | CoS documentation guard | negative | C/S: stale policy phrases and line breadcrumbs are rejected; M/C: recursive reads are owned and failures at roots/files panic; P: N/A; L: test-only tree scan; M/T: individual read_dir entry errors are flattened, but no production defect was established. |
| userspace-dp/tests/fairness_eval_blackbox.rs | Fairness CLI black-box suite | negative | C/S: exit codes, schema, gates, starvation, saturation, and malformed inputs are checked; M/C: temporary files are Drop-cleaned; P: fairness observability rather than forwarding parity; L: test-only subprocess work; M/T: all 1,366 lines and fixture builders were inspected. |
| userspace-dp/tests/snat_contract_doc_guard.rs | SNAT fail-closed drift guard | negative | C/S: both runtime call sites and failure recording are pinned; M/C: source scanning only; P: source-NAT semantics documented; L: test-only; M/T: string-window brittleness did not establish a runtime bug. |
| userspace-xdp/src/lib.rs | AF_XDP steering shim | A1-b6-F005 | C/S: ctrl/ingress/binding/session/degraded branches and endian handling were traced; M/C: typed metadata write lacks an alignment guarantee; P: steering behavior is the sole retained XDP role; L: no extra packet allocation, but undefined alignment is on every redirected packet; M/T: size/offset assertions omit alignment and no unaligned metadata test exists. |

Direct contracts inspected to confirm/refute candidates were:
userspace-dp/src/afxdp/coordinator/{mod.rs,snapshot_refresh.rs,reconcile/snapshot.rs},
userspace-dp/src/state_writer.rs, userspace-dp/src/protocol/{control.rs,snapshot.rs},
pkg/dataplane/userspace/{process.go,capabilities.go,maps_sync.go,manager_status.go},
pkg/daemon/daemon_ha_userspace_stream.go, pkg/dataplane/constants.go, and the
test systemd unit. They are not counted in the 31-file ledger.

### A2-b1: Rust NAT, NAT64, NPTv6 and translation (18 files)

Batch-list SHA-256: `c7b5f7f7852ce281de66eed4eeb0e329078bb840d215238e99a1a94a7681ae83`.

### NAT64

- `userspace-dp/src/nat64.rs` — **A2-b1-F004**. Correctness/security: traced prefix load, tri-state classification, BIB allocation/release/HA reservation, extension and fragment handling, ICMP-error translation, length checks, checksums, and both frame directions; the surviving defect is commit/runtime prefix grammar drift. Memory/concurrency/truncation/leaks: checked caller-buffer bounds, 4 KiB production-frame reachability, allocator ownership, bounded sharded fragment associations, expiry, release, and narrowing casts; no additional issue survived. vSRX: /96, deterministic NAPT64, DF policy, fragments, ICMP, and HA/reload behavior were compared; malformed-prefix commit parity is incomplete. Performance/modularity: transit writers are allocation-free and extension walks/cache scans are bounded; the 3,102-line module remains dense but no distinct modularity defect was retained. Tests: broad packet/checksum/fragment/HA coverage exists, but no cross-language exact-prefix grammar test.
- `userspace-dp/src/nat64_tests.rs` — **A2-b1-F004**. Correctness/security: all 4,447 lines were inspected, including fail-closed pool parsing, translation, ICMP, fragments, BIB uniqueness, HA reservation, reload, and checksum tests. Memory/concurrency/truncation/leaks: buffer-reuse, cache bound/TTL, allocator release, and malformed/truncated packet tests were checked. vSRX: runtime rejects an extra-slash prefix, exposing the validator mismatch. Performance/modularity: allocation-free and incremental-checksum regression tests are present; the large sibling test module is logically partitioned by comments. Tests: missing strict-commit/runtime parity and changed-but-overlapping-pool collision cases.

### NPTv6

- `userspace-dp/src/nptv6.rs` — **A2-b1-F001**. Correctness/security: traced parse, overlap rejection, adjustment math, inbound/outbound matching, and callers; `from_zone` is discarded before both translations. Memory/concurrency/truncation/leaks: immutable vectors and in-place address rewrites have no unsafe or lifetime issue; overlap handling is fail-closed but over-global. vSRX: rule-set scope is not enforced and valid multi-scope rules cannot hydrate. Performance/modularity: matching is a bounded config-vector scan with no allocation; the fix should use pre-resolved zone IDs rather than packet-path strings. Tests: no wrong-zone negative or multi-scope hydrate test.
- `userspace-dp/src/nptv6_tests.rs` — **A2-b1-F001**. Correctness/security: all 790 lines were inspected across /48 and /64 parsing, adjustment, round trips, overlap, host bits, composition, and checksum-neutral edge cases. Memory/concurrency/truncation/leaks: pure deterministic tests; no retained issue. vSRX: the sole non-empty `from_zone` fixture translates without supplying a zone, so it does not test scope. Performance/modularity: compact pure-function coverage. Tests: missing same-prefix/different-zone, same-logical-rule/multi-zone, and wrong-zone rejection cases.

### Source NAT and allocator

- `userspace-dp/src/nat/allocator.rs` — **A2-b1-F002, A2-b1-F003**. Correctness/security: audited bitmap claims, address selection, PAT probing, persistent leases, deterministic blocks, synced reserve, address-only ownership, release/rollback, and GC; synced address-only ownership is absent and address-only allocation does not mirror PAT's multi-address probe. Memory/concurrency/truncation/leaks: atomics, CAS ownership, mutex recovery, bounded maps, FIFO recycle, chunked GC, and teardown were checked; no unsafe memory issue survived. vSRX: address-only capacity semantics are under-enforced across HA and under-utilized within multi-address pools. Performance/modularity: PAT has bounded all-address probing and lock-free claims; address-only fixes can remain first-flow/collision-path work. Tests: no HA address-only reservation or occupied-start/free-next-address case.
- `userspace-dp/src/nat/mod.rs` — **negative**. Correctness/security: decision reverse/merge semantics and counter reset were checked; the reset candidate matched tracked #3830 and was suppressed. Memory/concurrency/truncation/leaks: relaxed atomics are non-owning telemetry; no memory issue. vSRX: NAT flags and translation composition are represented. Performance/modularity: constant-time decision operations; module boundaries are appropriate. Tests: counter interleavings remain a tracked, not new, concern.
- `userspace-dp/src/nat/source.rs` — **A2-b1-F002, A2-b1-F003**. Correctness/security: traced snapshot parse, scope/L4/address matching, pool-family selection, deterministic/PAT/address-only allocation, reload reuse, HA reserve, release, and failure attribution. Memory/concurrency/truncation/leaks: allocator ownership and teardown symmetry were checked. vSRX: `port no-translation` and port-less flows preserve ports, but HA and pool-capacity behavior diverge. Performance/modularity: ordinary PAT scans pool addresses only on first-flow allocation; address-only currently makes one attempt. Tests: local #5269 coverage exists but the missing HA and post-release cursor-wrap cases do not.
- `userspace-dp/src/nat/status.rs` — **negative**. Correctness/security: status DTO fields and defaulting were checked against allocator counters; no forwarding decision is made here. Memory/concurrency/truncation/leaks: owned scalar snapshot, no unsafe or lifetime risk. vSRX: exposes pool utilization dimensions needed operationally. Performance/modularity: 40-line isolated DTO. Tests: exercised through pool status tests; no distinct gap retained.
- `userspace-dp/src/nat/tests_counter.rs` — **negative**. Correctness/security: clear/add/subtract interleavings were inspected; the remaining packet/byte reset race is already tracked as #3830. Memory/concurrency/truncation/leaks: stress uses bounded threads/atomics. vSRX: telemetry only. Performance/modularity: focused counter suite. Tests: no new non-duplicate defect.
- `userspace-dp/src/nat/tests_l4_match.rs` — **negative**. Correctness/security: protocol, source/destination port, application expansion, impossible sentinels, and fail-closed malformed constraints were checked. Memory/concurrency/truncation/leaks: test-only bounded vectors. vSRX: Junos L4 matching precedence is covered. Performance/modularity: focused matcher tests. Tests: negative and composition cases were sufficient for assigned logic.
- `userspace-dp/src/nat/tests_pool.rs` — **A2-b1-F002, A2-b1-F003**. Correctness/security: all 4,673 lines were inspected across pool parsing, PAT, persistence, deterministic modes, address-only tokens, HA reserve, concurrency, recycle, capacity, and GC. Memory/concurrency/truncation/leaks: exact-cap, churn, leak, and chunked-GC tests are strong. vSRX: #5269 local capacity is tested, while the HA test explicitly classifies address-only as reserving nothing. Performance/modularity: lock-free and GC latency seams are exercised. Tests: the two retained address-only gaps are not covered.
- `userspace-dp/src/nat/tests_scope.rs` — **negative**. Correctness/security: zone, interface, routing-instance, mixed-scope AND behavior, and precedence were checked. Memory/concurrency/truncation/leaks: test-only immutable state. vSRX: source-NAT scope contracts are substantially covered. Performance/modularity: focused scope suite. Tests: no new defect survived; static scope candidate was duplicate-suppressed against #3605.
- `userspace-dp/src/nat/tests_source.rs` — **negative**. Correctness/security: interface mode, off, family, ordering, counters, malformed addresses, and merge behavior were checked. Memory/concurrency/truncation/leaks: no owning concurrency. vSRX: basic source-NAT semantics are covered. Performance/modularity: focused baseline suite. Tests: pool-specific gaps are correctly separated into `tests_pool.rs`.

### Destination NAT

- `userspace-dp/src/nat/destination.rs` — **negative**. Correctness/security: traced snapshot parse, host/CIDR keys, prefix lookup, protocol/port/source constraints, pool selection, duplicate replacement, scope, counters, and fail-closed sentinels. Memory/concurrency/truncation/leaks: immutable config tables plus atomics; no unsafe or unbounded packet-owned state. vSRX: zone/interface/routing-instance scope, L4 matches, named pools, and source constraints are represented. Performance/modularity: exact hash plus bounded prefix/config scans; large module but coherent ownership. Tests: malformed-prefix observability is weaker than ideal, but no credible new correctness bug survived.
- `userspace-dp/src/nat/tests_destination.rs` — **negative**. Correctness/security: all 1,770 lines were inspected across precedence, pools, scope, address names, duplicates, counters, ranges, and family behavior. Memory/concurrency/truncation/leaks: test-only bounded state. vSRX: broad destination-NAT parity coverage. Performance/modularity: focused despite size. Tests: no non-duplicate gap rose to a finding.
- `userspace-dp/src/nat/tests_dnat_proto.rs` — **negative**. Correctness/security: protocol-only and protocol+port selection, mismatch, and translation were checked. Memory/concurrency/truncation/leaks: test-only. vSRX: protocol matching is pinned. Performance/modularity: compact focused suite. Tests: adequate for the assigned branch.

### Static NAT

- `userspace-dp/src/nat/static_nat.rs` — **negative**. Correctness/security: traced exact/block mappings, source/port restrictions, scoped selection, reverse mapping, counters, and malformed-entry skips. Memory/concurrency/truncation/leaks: immutable config maps/vectors and atomics, no unsafe ownership. vSRX: bidirectional static mapping, blocks, ports, and scope are represented; the examined scope-order candidate matched tracked #3605. Performance/modularity: hash lookup plus bounded scoped candidate scans. Tests: overlap/scope history is tracked; no new issue survived strict deduplication.
- `userspace-dp/src/nat/tests_static.rs` — **negative**. Correctness/security: all 1,198 lines were inspected across exact/block, reverse, source, ports, scope, counters, malformed entries, and replacement behavior. Memory/concurrency/truncation/leaks: test-only bounded state. vSRX: major static-NAT contracts are covered. Performance/modularity: focused regression suite. Tests: no new non-duplicate defect.

### A3-b1: Go configuration compiler, schema and CLI grammar (23 files)

Batch-list SHA-256: `aab9f11178132d8ba9b0d7c2fa466bb59abeb3ba282e7ed0da283ca85a19b02e`.

### Application catalog, runtime resolution, and status rendering

Review dimensions:

- Correctness/security/fail-open: checked sorted app-id assignment, the reserved-zero/uint16 boundary, malformed and explicit-zero port handling, explicit protocol 0 versus omitted/unrepresentable protocols, application-set expansion, nil tolerant-load shapes, ICMP type/code honesty, enabled/disabled name resolution, source/destination port matching, and renderer/runtime agreement. Malformed rows generally fail closed. `A3-b1-F001` survives on the disabled fallback's algorithmic cost.
- Memory safety/concurrency/truncation/leaks: this Go slice has no unsafe or raw-pointer code. Catalog IDs narrow only after the uint32 boundary guard; ports narrow only after bounded parsing. Config and name maps are consumed as immutable snapshots. Package race tests passed. No leak or data-race candidate survived; `A3-b1-F001` is computational amplification rather than memory corruption.
- vSRX feature completeness: the status renderer honestly states that AppID is L3/L4 tuple matching, not DPI. Type-constrained ICMP is deliberately rendered UNKNOWN rather than falsely labeled until the wire supports type/code. No new non-duplicate vSRX parity defect survived.
- Performance/latency: catalog construction is apply-time and capped by the app-id space. The disabled session fallback performs a full application scan and reparses specs for each unstamped session; this is `A3-b1-F001`.
- Modularity/test gaps: `ProtocolNumber` is the protocol SSOT and parity tests cover catalog/compiler ordering and Rust fixture precedence. Tests cover many malformed shapes but contain no scaling assertion or benchmark for session count multiplied by application count.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/appid/catalog.go` | Catalog compiler | negative | IDs remain 1..65535, malformed protocol/ports emit no over-broad row, explicit protocol 0 stays distinct from unknown, and emitted rows resolve through `AppNames`; boundary-order and signed-port candidates were duplicate/refuted. |
| `pkg/appid/catalog_bad_protocol_4887_test.go` | Catalog malformed protocol tests | negative | Unrepresentable explicit protocols produce neither a row nor a stampable name, while literal protocol 0 remains representable. |
| `pkg/appid/catalog_icmp_3781_test.go` | ICMP catalog/fallback tests | negative | Type/code-constrained ICMP cannot degrade to a protocol-only false label; protocol-only ICMP and unrelated TCP remain usable. |
| `pkg/appid/catalog_nil_app_4865_test.go` | Tolerant-load nil application tests | negative | Nil application map values neither panic catalog construction nor tuple fallback and do not consume/stamp an ID. |
| `pkg/appid/catalog_nil_appset_5179_test.go` | Application-set expansion tests | negative | A present-but-nil application-set fails with a deterministic expansion error rather than a panic. |
| `pkg/appid/catalog_port_zero_5194_test.go` | Port sentinel tests | negative | Explicit 0/0-0 never aliases the unconstrained `(0,0)` wire sentinel; 0-N narrows to 1-N. |
| `pkg/appid/catalog_proto0_4008_test.go` | Protocol-zero fan-out tests | negative | Explicit protocol 0 emits only protocol 0; only an absent protocol takes the legacy TCP/UDP fan-out path. |
| `pkg/appid/catalog_tolerant_3725_test.go` | Malformed tolerant-load catalog tests | negative | Bad source ports, inverted ranges, and dangling names fail closed without shifting valid catalog IDs. |
| `pkg/appid/precedence_parity_test.go` | Go/Rust precedence fixture | negative | BuildCatalog IDs/rows and disabled Go tuple precedence agree with the shared Rust fixture for covered user-app overlap tiers. |
| `pkg/appid/protocol_lenient_3439_test.go` | Protocol filter parser tests | negative | Lenient operator parsing accepts every canonical rendered protocol and rejects out-of-range/junk tokens. |
| `pkg/appid/protocol_number_2124_test.go` | Protocol SSOT drift guards | negative | Named/alias/numeric resolution, display round trips, filter-gate parity, and TCP/UDP-only port-bearing parity remain pinned. |
| `pkg/appid/runtime.go` | Session application resolution | `A3-b1-F001` | Name resolution is deterministic and malformed specs fail closed, but every unstamped session in disabled mode scans and reparses the full user application map. |
| `pkg/appid/runtime_test.go` | Runtime functional tests | negative | AppID/UNKNOWN behavior, tuple specificity, canonical ports, source-port constraints, nil shapes, NAT references, and ID boundaries are covered; no large-map/session scaling case exists. |
| `pkg/appid/textrender.go` | Operator status renderer | negative | Nil/disabled/enabled output matches the implemented tuple fallback ordering and states unsupported DPI features without claiming enforcement. |
| `pkg/appid/textrender_test.go` | Status renderer tests | negative | Enabled honesty, disabled user-app-first ordering, and nil-config sentinel are asserted. |

### Operational command tree and completion grammar

Review dimensions:

- Correctness/security/fail-open: checked static prefix resolution, placeholder descent, typed and dynamic value consumption, canonicalized context words, nil provider behavior, and every dynamic provider's nil guards. Nil tolerant-load cases are handled. `A3-b1-F002` and `A3-b1-F003` survive as grammar/completion defects; command execution and config enforcement are not widened.
- Memory safety/concurrency/truncation/leaks: `OperationalTree` and `ConfigTopLevel` are read-only process globals in these paths. Completion allocates bounded candidate slices from current configuration and has no unsafe code. Race tests passed; no mutation, leak, truncation, or concurrent-map candidate survived under the immutable-config contract.
- vSRX feature completeness: the assigned HA/security/CoS drill-downs exist. `A3-b1-F002` is a CLI parity/usability gap for a supported policy diagnostic; it is not evidence of missing policy enforcement.
- Performance/latency: completion walks are control-plane only. Dynamic providers scan their relevant configured collections once per request; no credible non-duplicate latency defect survived.
- Modularity/test gaps: cmdtree is the operational grammar SSOT for local CLI, remote CLI, and gRPC. The two completion walkers duplicate traversal state. Tests cover nil providers, placeholders, keyword abbreviation, and selected command presence, but omit mandatory scalar value transitions and dynamic-value/keyword collisions.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/cmdtree/completion_nil_3476_test.go` | Policy-name context completion | negative | Nil zone-pair and policy entries are skipped while valid policy names remain visible. |
| `pkg/cmdtree/completion_nil_3493_test.go` | Packet-drop zone completion | negative | Nil zone values no longer panic or create an empty candidate; the adjacent canonical-name concern is duplicate of tracked #3493 and was suppressed. |
| `pkg/cmdtree/completion_nil_provider_5196_test.go` | Nil-config dynamic providers | negative | Static providers still run with nil active config and return main route tables/protocols in both completion APIs. |
| `pkg/cmdtree/completion_nil_ri_rg_4866_test.go` | RI/RG completion | negative | Nil routing-instance and redundancy-group elements are skipped across all shared providers. |
| `pkg/cmdtree/completion_zone_prefix_5196_test.go` | Context keyword canonicalization | negative | Accepted abbreviations of `from-zone`/`to-zone` reach context providers as canonical keywords; this does not cover `A3-b1-F003`. |
| `pkg/cmdtree/tree.go` | Operational grammar and walkers | `A3-b1-F002`, `A3-b1-F003` | Mandatory value slots must consume one value before child keywords, and dynamic configured values must not be stolen by child-keyword prefix resolution. |
| `pkg/cmdtree/tree_hb167_test.go` | Required drill-down presence | negative | IKE/IPsec SA detail, static NAT rule detail, and policy check nodes are present and non-nil. |
| `pkg/cmdtree/tree_test.go` | Core completion behavior | negative | Placeholder descent/stay-level, dynamic RG/table names, unique/ambiguous prefixes, descriptions, DDNS, and CoS nodes are covered; mandatory scalar values and collisions are not. |

### A3-b2: Go configuration compiler, schema and CLI grammar (135 files)

Batch-list SHA-256: `679b98481b0848908035b86aa0ca530988453670ad905a51731788efdb175ed1`.

### Five-dimension assessment

| Module | Correctness / security | Memory / concurrency / truncation / leak | vSRX completeness | Performance | Modularity | Tests |
|---|---|---|---|---|---|---|
| AST, edits, formatting, groups, redaction | Checked full-key navigation, merge precedence, duplicate rendering, inactive handling, and secret masking. | Checked clone ownership, slice mutation, recursion depth/work budgets, and malformed-node indexing. | Compared flat-set, hierarchical, bracket-list, wildcard, `${node}`, and inherited forms. | Checked group memoization/work caps and formatter traversal. | Responsibilities are split across AST/edit/format/group/redact helpers; no new coupling finding retained. | Assigned regressions cover group depth/transitivity/leaf lists, rendering, and redaction; two same-root candidates were suppressed. |
| Core compiler, routing, chassis | Checked prewalk ordering, strict/lenient routing, collision gates, enum/range parsing, and derivations. | Checked clone-before-mutate, bounded worker knobs, integer conversion, and nil handling. | Checked common vSRX backup-router, BGP, chassis, and default-policy forms. | Checked early rejection and bounded compile work; no hot-path work added by these files. | Dispatch and early/tail validation remain separated from subsystem compilers. | Assigned regressions cover backup-router, BGP, default policy, device maps, and duplicate blocks. |
| Applications and address references | Checked name collisions, generated terms, application-set expansion, protocol/port semantics, and undefined references. | Checked recursive set expansion and list accumulation for truncation or cycles. | Checked predefined Junos applications, direct/term forms, ALG advisories, and bracket members. | Catalog/set walks are bounded by configuration size; no new amplification retained. | Collision and application compilation are separated cleanly. | Assigned tests cover malformed specs, collisions, nested sets, aliases, timeouts, and mixed direct/term syntax. |
| CoS, firewall, interfaces | Checked classifier/rewrite domains, family-any parity, filter actions/references, interface-range expansion, and unsupported stanza gates. | Checked numeric overflow, panic surfaces, list expansion caps, and aliasing. `A3-b2-F001` violates the intended 4096-member bound. | Checked inet/inet6/any, reth/fabric, QinQ, CoS aliases, and flat/hierarchical parity. | Checked expansion caps and compile-time list growth; `A3-b2-F001` is an unbounded control-plane loop. | Family-specific validators and unsupported-stanza prewalks are localized. | Assigned tests cover family collisions, bounds, interface ranges, reth/fabric node selection, and CoS validation. |
| DDNS and DHCP | Checked credential transport, duration parsing, relay overrides, provider validation, and redaction. `A3-b2-F002` is a TLS-classification bypass. | Checked secret copies, URL/error redaction, client ownership, and list parsing; no new leak other than transport disclosure. | Checked dyndns2, generic, Cloudflare, Route53, DuckDNS, RFC2136, and dual-family DHCP-DDNS forms. | Provider checks are linear in configured providers; no new hot-path cost retained. | TLS classification is isolated, but its predicate is narrower than the generic backend contract. | Assigned tests cover configured credentials over HTTP, malformed provider URLs, durations, and relay/DDNS forms; literal userinfo is untested. |
| IPsec | Checked proposal/policy/gateway references, bind-interface grammar, selector shapes, proposal sets, and strict/lenient behavior. | Checked nil maps/pointers, list truncation, integer parsing, and bounded selector walks. | Checked v1/v2, proposal-set shorthands, manual/AH rejection, st interfaces, and traffic selectors. | Selector and proposal walks are configuration-linear. | Bind-interface, proposal-set, and traffic-selector validation are separated. | Assigned tests cover collisions, references, multi-proposals, reserved names, and selector injection/shape validation. |
| NAT and NPTv6 | Checked source/destination/static/NAT64 parsing, scope, application references, ports, host masks, prefix families, and runtime parity. `A3-b2-F003` through `F005` are retained. | Checked range expansion bounds, integer conversion, address-list truncation, and map/list growth. | Checked host/block static NAT, NAT64 `/96`, NPTv6, pools, persistent NAT, and flat/hierarchical forms. | Checked bounded port/address expansion and no per-packet changes; findings are compile/apply correctness issues. | NAT remains large and validation is split across compiler/schema/runtime contracts, which enabled the three retained drifts. | Assigned tests are extensive for valid/reversed/out-of-range forms but omit extra-slash NAT64, nonnumeric source-pool range endpoints, and nonnumeric static mapped ports. |
| Security policies | Checked duplicate match/then blocks, required dimensions, global-zone context, terminal actions, and inert logging. | Checked list accumulation and nil tolerance; no concurrency ownership in this compiler slice. | Checked zone-pair/global policies, `junos-host`, deny/reject/permit, and duplicate hierarchy. | Policy walks are configuration-linear. | Match compilation and strict policy gates remain separate. | Assigned tests cover duplicate blocks/names, global-zone matching, and deny-log advisories. |

### Complete coverage ledger

Every manifest path appears exactly once below. `Negative` means the file was inspected and the stated invariant was checked without retaining a new, nonduplicate finding.

| # | Path | Module | Result |
|---:|---|---|---|
| 1 | `pkg/config/addressbook_dup_addrset_merge_4706_test.go` | Applications/address book | Negative: duplicate address-set definitions retain the merged membership rather than truncating a sibling. |
| 2 | `pkg/config/addressbook_name_slash_3061_test.go` | Applications/address book | Negative: slash-bearing address-book names are rejected/resolved consistently across strict and tolerant paths. |
| 3 | `pkg/config/addressbook_name_slash_4340_test.go` | Applications/address book | Negative: reserved/slash name handling remains covered across parser shapes. |
| 4 | `pkg/config/addressset_bracket_members_4791_test.go` | Applications/address book | Negative: every bracket-list address-set member is retained. |
| 5 | `pkg/config/allow_dataplane_sleep_test.go` | Core compiler | Negative: dataplane-sleep opt-in parsing and default behavior remain explicit. |
| 6 | `pkg/config/application_set_nested_test.go` | Applications | Negative: nested application sets expand without dropped members or unresolved cycles. |
| 7 | `pkg/config/applicationset_bracket_members_5181_test.go` | Applications | Negative: bracketed application-set members are read across both AST representations. |
| 8 | `pkg/config/apply_groups_depth_5194_test.go` | AST/groups | Negative: depth and total-work limits reject pathological group expansion. |
| 9 | `pkg/config/apply_groups_leaflist_exclude_test.go` | AST/groups | Negative: non-leaf-list/range-bearing statements do not receive accidental union semantics. |
| 10 | `pkg/config/apply_groups_leaflist_test.go` | AST/groups | Negative: typed leaf-list inheritance unions and deduplicates both AST shapes. |
| 11 | `pkg/config/apply_groups_transitive_4474_test.go` | AST/groups | Negative: transitive expansion, cycle rejection, memoization, and fan-out bounds are covered. |
| 12 | `pkg/config/archival_leading_dash_4589_test.go` | Core compiler | Negative: leading-dash archival values are rejected rather than becoming command options. |
| 13 | `pkg/config/ast.go` | AST/core | Negative: clone and read-all-sibling navigation reviewed; CopyPath first-prefix behavior was suppressed as the same root as tracked #3982. |
| 14 | `pkg/config/ast_edit.go` | AST/edit | Negative: set/delete/rename/activate list-member semantics reviewed; no nonduplicate edit finding retained. |
| 15 | `pkg/config/ast_format.go` | AST/format | Negative: escaping, inactive markers, repeated-leaf arrays, and path rendering inspected. |
| 16 | `pkg/config/ast_groups.go` | AST/groups | Negative: typed precedence, memo ownership, recursion depth, and work budget inspected. |
| 17 | `pkg/config/ast_redact.go` | AST/redaction | Negative: qualifier-preserving secret masking covers the assigned secret keyword set. |
| 18 | `pkg/config/ast_redact_test.go` | AST/redaction | Negative: raw AST render surfaces and qualifier preservation are regression-covered. |
| 19 | `pkg/config/backup_router_family_2911_test.go` | Core/routing | Negative: backup-router next-hop/destination family mismatch is rejected. |
| 20 | `pkg/config/backup_router_format_4808_test.go` | Core/routing | Negative: malformed backup-router addresses fail strict compile and downgrade on tolerant load. |
| 21 | `pkg/config/bgp_as_wrap_4713_test.go` | Core/routing | Negative: AS values cannot wrap/truncate into the typed BGP fields. |
| 22 | `pkg/config/bgp_group_inherit_order_5270_test.go` | Core/routing | Negative: BGP group inheritance is order-independent. |
| 23 | `pkg/config/bgp_neighbor_peeras_2963_test.go` | Core/routing | Negative: neighbor peer-AS parsing and override behavior are covered. |
| 24 | `pkg/config/bgp_peeras_range_4589_test.go` | Core/routing | Negative: peer-AS range bounds reject invalid values. |
| 25 | `pkg/config/compile_golden_4406_test.go` | Core compiler | Negative: deterministic typed-config golden coverage inspected; the golden test was not run to avoid mismatch artifact writes. |
| 26 | `pkg/config/compiler.go` | Core compiler | Negative: clone/prune, prewalk order, group expansion, strict/lenient options, and tail gates inspected. |
| 27 | `pkg/config/compiler_addrbook_warn_3958_test.go` | Applications/address book | Negative: valid address-reference forms avoid false warnings while undefined references remain visible. |
| 28 | `pkg/config/compiler_application_destport_names_3340_test.go` | Applications | Negative: named ports resolve case-insensitively and unknown names fail closed. |
| 29 | `pkg/config/compiler_application_junos_ping_3348_test.go` | Applications | Negative: Junos ping aliases compile to constrained ICMP types; malformed constraints reject. |
| 30 | `pkg/config/compiler_application_mixed_term_3366_test.go` | Applications | Negative: mixed direct/term definitions and duplicate scalar leaves reject deterministically. |
| 31 | `pkg/config/compiler_application_port_range_zero_4336_test.go` | Applications | Negative: legal zero-floor application port ranges are not over-rejected. |
| 32 | `pkg/config/compiler_application_set_member_3890_test.go` | Applications | Negative: misspelled member keywords reject in referenced and unreferenced sets. |
| 33 | `pkg/config/compiler_application_specs_test.go` | Applications | Negative: malformed ports/protocols/protocolless and non-port protocol combinations are covered. |
| 34 | `pkg/config/compiler_application_term_alg_3352_3353_test.go` | Applications | Negative: unknown term leaves reject while unsupported ALG names remain explicit advisories. |
| 35 | `pkg/config/compiler_application_timeout_3320_test.go` | Applications | Negative: timeout aliases/ranges and schema validation are covered. |
| 36 | `pkg/config/compiler_applications.go` | Applications | Negative: direct/term compilation, catalog expansion, list retention, and reference semantics inspected. |
| 37 | `pkg/config/compiler_applications_collision.go` | Applications | Negative: authored/generated app and set namespace collisions are checked before map overwrite. |
| 38 | `pkg/config/compiler_applications_collision_3339_test.go` | Applications | Negative: duplicate/cross-kind/generated-name collisions across repeated blocks are covered. |
| 39 | `pkg/config/compiler_as_path_prepend_2892_test.go` | Core/routing | Negative: single and bracketed AS-path prepend values retain order. |
| 40 | `pkg/config/compiler_bgp_as_3870_test.go` | Core/routing | Negative: autonomous-system inheritance and local-AS precedence are covered. |
| 41 | `pkg/config/compiler_chassis.go` | Chassis | Negative: unmapped-interface policy and device-map dispatch inspected. |
| 42 | `pkg/config/compiler_chassis_device_map_test.go` | Chassis | Negative: duplicate identities, missing identities, node alignment, normalization, and lenient behavior are covered. |
| 43 | `pkg/config/compiler_class_of_service.go` | CoS | Negative: code-point domains, scheduler maps, rates, queue bounds, and strict/lenient propagation inspected. |
| 44 | `pkg/config/compiler_cluster_authkey_4107_test.go` | Chassis | Negative: cluster authentication key compilation and render redaction are covered. |
| 45 | `pkg/config/compiler_cos_fc_queue_4594_test.go` | CoS | Negative: forwarding-class queue bounds reject negative and over-255 values. |
| 46 | `pkg/config/compiler_cos_rate_percent_strict_4320_test.go` | CoS | Negative: NaN/Inf percentages reject while finite values pass. |
| 47 | `pkg/config/compiler_cos_tcp_hb167_test.go` | CoS | Negative: traffic-control-profile inheritance, unit precedence, and advisories are covered. |
| 48 | `pkg/config/compiler_ddns_duration_4837_test.go` | DDNS | Negative: malformed/nonpositive durations reject strictly and warn tolerantly. |
| 49 | `pkg/config/compiler_ddns_tls.go` | DDNS/security | `A3-b2-F002`: literal userinfo is omitted from credential classification. |
| 50 | `pkg/config/compiler_ddns_tls_4861_test.go` | DDNS/security | Negative: configured credential fields and `%u`/`%p` over plaintext are covered; literal userinfo is the missing case in `F002`. |
| 51 | `pkg/config/compiler_default_policy_3065_test.go` | Core/security | Negative: absent and explicit default policies preserve fail-closed behavior. |
| 52 | `pkg/config/compiler_default_policy_log_3534_test.go` | Core/security | Negative: default-policy logging compiles and inert deny logging warns. |
| 53 | `pkg/config/compiler_derivations.go` | Core compiler | Negative: loopback/fabric/address derivations and nil/unit guards inspected. |
| 54 | `pkg/config/compiler_dhcp_ddns_test.go` | DHCP/DDNS | Negative: flat/hierarchical, dual-family, TSIG redaction, schema, and backend advisories are covered. |
| 55 | `pkg/config/compiler_dhcp_relay_overrides_test.go` | DHCP | Negative: relay override tokens are not swallowed across packed and block forms. |
| 56 | `pkg/config/compiler_dispatch.go` | Core compiler | Negative: top-level repeated-block dispatch and subsystem merge behavior inspected. |
| 57 | `pkg/config/compiler_dnat_address_test.go` | NAT | Negative: valid lists and partial/all-invalid DNAT destinations fail or compile as intended. |
| 58 | `pkg/config/compiler_dnat_protocol_test.go` | NAT | Negative: protocol normalization resolves known names and rejects unknown names. |
| 59 | `pkg/config/compiler_dup_flow_subblock_3566_test.go` | Core/security | Negative: strict flow/log gates inspect duplicate subblocks rather than first-only. |
| 60 | `pkg/config/compiler_dup_match_then_3850_test.go` | NAT/firewall | Negative: duplicate match/from blocks accumulate and terminal actions retain last-block semantics safely. |
| 61 | `pkg/config/compiler_dup_policy_name_3473_test.go` | Policies | Negative: duplicate policy names reject per context while cross-context reuse remains valid. |
| 62 | `pkg/config/compiler_dup_security_3562_test.go` | Policies/IPsec | Negative: security prewalks inspect every repeated top-level security block. |
| 63 | `pkg/config/compiler_dynamic_address_feed_ref_3300_test.go` | Applications/address book | Negative: feed references and server endpoint shapes are validated. |
| 64 | `pkg/config/compiler_earlystrict.go` | Core compiler | Negative: post-fold resolution and early strict gate ordering inspected. |
| 65 | `pkg/config/compiler_equal_flow_target_policy_test.go` | CoS | Negative: enum values, warnings, cost advisory, schema, and completion are covered. |
| 66 | `pkg/config/compiler_equal_flow_worker_cap_test.go` | CoS | Negative: equal-flow values above a legacy worker cap retain node parity. |
| 67 | `pkg/config/compiler_f3_hb167_test.go` | Firewall/CoS | Negative: interface-specific and accepted-inert CoS coverage is explicit. |
| 68 | `pkg/config/compiler_feed_address_token_3294_test.go` | Applications/address book | Negative: direct feed bindings resolve while feeds nested in sets reject. |
| 69 | `pkg/config/compiler_feed_url_malformed_5183_test.go` | Applications/address book | Negative: malformed feed URLs reject at strict compile. |
| 70 | `pkg/config/compiler_filter_action_test.go` | Firewall | Negative: unknown/ambiguous terminal actions reject rather than defaulting. |
| 71 | `pkg/config/compiler_filter_loss_priority_2507_test.go` | Firewall | Negative: loss-priority values are preserved and validated. |
| 72 | `pkg/config/compiler_filter_nocatchall_3295_test.go` | Firewall | Negative: filters without a catch-all preserve intended term semantics. |
| 73 | `pkg/config/compiler_filter_protocol_test.go` | Firewall | Negative: protocol symbols normalize and unresolved values reject. |
| 74 | `pkg/config/compiler_filter_ref_3296_test.go` | Firewall/interfaces | Negative: undefined interface filter hooks reject rather than disabling enforcement. |
| 75 | `pkg/config/compiler_firewall.go` | Firewall | Negative: family walks, match accumulation, flexible-match parsing, and action compilation inspected. |
| 76 | `pkg/config/compiler_firewall_family_any_4287_test.go` | Firewall | Negative: family-any compiles both arms and cross-family collisions reject. |
| 77 | `pkg/config/compiler_firewall_family_any_match_4296_test.go` | Firewall | Negative: family-specific matches under family-any reject; agnostic matches pass. |
| 78 | `pkg/config/compiler_firewall_family_any_prefixlist_4426_test.go` | Firewall | Negative: single-family prefix lists under family-any reject with directionally correct impact. |
| 79 | `pkg/config/compiler_firewall_family_bounds_4827_test.go` | Firewall | Negative: empty-key malformed ASTs no longer panic in the covered firewall family paths. |
| 80 | `pkg/config/compiler_firewall_family_collision_3884_test.go` | Firewall | Negative: cross-family same-name collisions reject; inet/inet6 coexistence remains valid. |
| 81 | `pkg/config/compiler_flat_reth_nodeid_4329_test.go` | Interfaces/chassis | Negative: flat reth/fabric local-member selection follows runtime node identity without clobbering explicit node leaves. |
| 82 | `pkg/config/compiler_frr_policy_inject_4097_test.go` | Core/security | Negative: control characters in FRR policy values reject/sanitize across strict/tolerant paths. |
| 83 | `pkg/config/compiler_inert_knobs_4306_test.go` | Core compiler | Negative: accepted-inert SNMP/system knobs warn without exposing secret material. |
| 84 | `pkg/config/compiler_interface_range.go` | Interfaces | `A3-b2-F001`: a MaxInt singleton member-range wraps the loop induction variable and defeats the expansion bound. |
| 85 | `pkg/config/compiler_interface_range_4027_test.go` | Interfaces | Negative: normal ranges and prior `en-sn+1` overflow are covered; the MaxInt singleton termination case in `F001` is absent. |
| 86 | `pkg/config/compiler_interfaces.go` | Interfaces | Negative: interface/unit/tunnel/VRRP parsing inspected; empty-key family panic candidate suppressed as same root as #4827. |
| 87 | `pkg/config/compiler_interfaces_unsupported.go` | Interfaces | Negative: unsupported MAC/ARP-policer/QinQ prewalk covers both AST forms and inherited config. |
| 88 | `pkg/config/compiler_interfaces_unsupported_test.go` | Interfaces | Negative: unsupported-stanza reject/warn behavior and false-positive controls are covered. |
| 89 | `pkg/config/compiler_ipsec.go` | IPsec | Negative: proposals, policies, gateways, IDs, DPD, and VPN field parsing inspected. |
| 90 | `pkg/config/compiler_ipsec_bindiface.go` | IPsec | Negative: canonical `st<N>[.unit]` parsing and alias-collision validation are bounded and deterministic. |
| 91 | `pkg/config/compiler_ipsec_bindiface_2933_test.go` | IPsec | Negative: ambiguous bind-interface aliases reject; unambiguous forms pass. |
| 92 | `pkg/config/compiler_ipsec_bindiface_validate_5297_test.go` | IPsec | Negative: invalid names reject in compile/schema and warn on tolerant load. |
| 93 | `pkg/config/compiler_ipsec_gateway_ref_test.go` | IPsec | Negative: dangling/addressless gateways reject and endpoint shape/length checks are covered. |
| 94 | `pkg/config/compiler_ipsec_hb167_parity_test.go` | IPsec | Negative: proposal sets, AH/manual-key rejection, monitor advisory, and tunnel enums are covered. |
| 95 | `pkg/config/compiler_ipsec_proposals_multivalue_3904_test.go` | IPsec | Negative: all proposal references survive bracket/block forms and dangling later references reject. |
| 96 | `pkg/config/compiler_ipsec_proposalset.go` | IPsec | Negative: synthetic proposal namespace reservation and deterministic expansion inspected. |
| 97 | `pkg/config/compiler_ipsec_reserved_proposal_name_5195_test.go` | IPsec | Negative: reserved synthetic names reject strictly and preserve authored crypto tolerantly. |
| 98 | `pkg/config/compiler_ipsec_trafficselector.go` | IPsec | Negative: control/whitespace and basic host/CIDR/range shape validation inspected; mixed-family range candidate was dropped pending renderer-parser confirmation. |
| 99 | `pkg/config/compiler_ipsec_ts_4098_test.go` | IPsec | Negative: injection, malformed shapes, tolerant warnings, and valid host/range/CIDR controls are covered. |
| 100 | `pkg/config/compiler_junos_host_direct_warn_4146_test.go` | Policies | Negative: direct `junos-host` delivery warnings distinguish enforced and unenforced cases. |
| 101 | `pkg/config/compiler_lo0_mirror_modifiers_3445_test.go` | Firewall/interfaces | Negative: lo0 kernel-mirror modifier advisories and false-positive controls are covered. |
| 102 | `pkg/config/compiler_nat.go` | NAT | `A3-b2-F003`, `A3-b2-F004`, `A3-b2-F005`: NAT64 delimiter drift and two malformed-port erasure paths. |
| 103 | `pkg/config/compiler_nat64_prefix_test.go` | NAT64 | Negative: address family/mask validation is broad, but no extra-slash case covers `F003`. |
| 104 | `pkg/config/compiler_nat_address_name_feed_3418_test.go` | NAT | Negative: direct feed-backed address names are accepted on all source/destination match paths. |
| 105 | `pkg/config/compiler_nat_address_name_resolvable_3425_test.go` | NAT | Negative: empty/prefixless names reject while resolvable/feed entries pass. |
| 106 | `pkg/config/compiler_nat_application_specs_test.go` | NAT/applications | Negative: NAT references cannot bypass malformed application-spec validation. |
| 107 | `pkg/config/compiler_nat_dest_address_name_3229_test.go` | NAT | Negative: destination-address-name parsing/reference checks cover SNAT and DNAT. |
| 108 | `pkg/config/compiler_nat_dnat_off_3844_test.go` | NAT | Negative: destination-NAT `off` compiles as an explicit exemption. |
| 109 | `pkg/config/compiler_nat_dnat_pool_3450_test.go` | NAT | Negative: DNAT pool port/address bounds, raw malformed preservation, and valid address-port forms are covered. |
| 110 | `pkg/config/compiler_nat_dnat_port_range_3449_test.go` | NAT | Negative: overlarge ranges are not expanded and valid ranges remain bounded. |
| 111 | `pkg/config/compiler_nat_dnat_to.go` | NAT | Negative: unsupported destination-NAT `to` scopes are found across repeated hierarchy. |
| 112 | `pkg/config/compiler_nat_dnat_to_3444_test.go` | NAT | Negative: strict/warn behavior and duplicate security/NAT/destination block traversal are covered. |
| 113 | `pkg/config/compiler_nat_dup_subblock_3915_test.go` | NAT | Negative: repeated source/destination/static/NAT64/proxy-ARP blocks merge instead of first-only truncation. |
| 114 | `pkg/config/compiler_nat_host_mask_test.go` | NAT | Negative: host/block/family/parseability and block-plus-port invariants are covered; nonnumeric mapped-port erasure in `F005` is not. |
| 115 | `pkg/config/compiler_nat_match_application_3434_test.go` | NAT/applications | Negative: undefined/empty application references reject; valid references compile. |
| 116 | `pkg/config/compiler_nat_match_dport_3446_test.go` | NAT | Negative: invalid destination-port tokens are preserved for strict rejection. |
| 117 | `pkg/config/compiler_nat_match_multivalue_3431_test.go` | NAT | Negative: every source/destination/protocol/application list value is retained. |
| 118 | `pkg/config/compiler_nat_mixed_scope.go` | NAT | Negative: incompatible from/to scope kinds are rejected rather than reduced. |
| 119 | `pkg/config/compiler_nat_mixed_scope_4881_test.go` | NAT | Negative: mixed-scope validation matrix and valid same-kind combinations are covered. |
| 120 | `pkg/config/compiler_nat_persistent_permit_test.go` | NAT | Negative: persistent-NAT three-way permit enum/default/schema behavior is covered. |
| 121 | `pkg/config/compiler_nat_pool_alarm_test.go` | NAT | Negative: alarm defaults, inversion, equality, range, and tolerant behavior are covered. |
| 122 | `pkg/config/compiler_nat_reversed_port_range_4422_test.go` | NAT | Negative: reversed match/source-pool ranges reject while forward controls pass. |
| 123 | `pkg/config/compiler_nat_scope_3079_test.go` | NAT | Negative: zone/interface/routing-instance scopes are captured on strict and tolerant paths. |
| 124 | `pkg/config/compiler_nat_source_address_name_2416_test.go` | NAT | Negative: source-address-name parsing/reference checks cover SNAT and DNAT. |
| 125 | `pkg/config/compiler_nat_source_dport_3429_test.go` | NAT | Negative: source-NAT destination-port scalar/range/bracket forms are retained. |
| 126 | `pkg/config/compiler_nat_source_pool_address_4521_test.go` | NAT | Negative: source-pool discrete/list/range/block address forms retain all addresses. |
| 127 | `pkg/config/compiler_nat_source_pool_port_3906_test.go` | NAT | Negative: valid/reversed/out-of-range source-pool ports are covered; nonnumeric endpoint fallback in `F004` is absent. |
| 128 | `pkg/config/compiler_nat_target_parity_hb167_test.go` | NAT | Negative: prefix-name resolution, empty targets, and accepted-inert routing-instance/overload knobs are covered. |
| 129 | `pkg/config/compiler_nptv6_self_overlap_4339_test.go` | NPTv6 | Negative: one rule across multiple scopes is not self-overlap; genuine overlaps still reject. |
| 130 | `pkg/config/compiler_nptv6_test.go` | NPTv6 | Negative: parseability, length/family, host bits, overlaps, and tolerant behavior are comprehensively covered. |
| 131 | `pkg/config/compiler_p3_http_providers_test.go` | DDNS | Negative: provider compilation and URL validators are covered; accepted URL userinfo confirms the contract used by `F002`. |
| 132 | `pkg/config/compiler_policy_dup_block_3842_test.go` | Policies | Negative: duplicate match blocks accumulate and conflicting/unsupported then blocks reject. |
| 133 | `pkg/config/compiler_policy_global_zone_3148_test.go` | Policies | Negative: global policy zone contexts, undefined zones, `any`, and `junos-host` behavior are covered. |
| 134 | `pkg/config/compiler_policy_log_inert_deny_4373_test.go` | Policies | Negative: deny/reject log advisories fire without false positives on permit/no-log policies. |
| 135 | `pkg/config/compiler_policy_match.go` | Policies | Negative: zone-pair/global match accumulation and duplicate hierarchy traversal inspected. |

### A3-b3: Go configuration compiler, schema and CLI grammar (135 files)

Batch-list SHA-256: `1a62a086ed54200e8e35ee4d22549f8cdcea635d6851c9f3ce3f028f7b1ff5f4`.

Dimensions used in every row: **1** correctness, security, and fail-open behavior; **2** memory safety, concurrency, truncation, and leaks; **3** vSRX feature completeness; **4** performance and packet/control-path latency; **5** modularity and test gaps. `1-5` means all dimensions were checked, with the last column naming the focal invariant. `negative` means no credible non-duplicate finding survived across those dimensions.

### Policy, prewalk, routing, and RPM

| Path | Module/subsystem | Result | Dims | Invariant checked |
|---|---|---|---|---|
| `pkg/config/compiler_policy_match_3113_test.go` | security policy grammar | negative | 1-5 | Unsupported match leaves reject strictly and warn only on tolerant load. |
| `pkg/config/compiler_policy_match_3142_test.go` | security policy grammar | negative | 1-5 | Multi-value tails cannot absorb unsupported match keywords. |
| `pkg/config/compiler_policy_match_3673_test.go` | security policy grammar | negative | 1-5 | Reserved zone tokens cannot be swallowed as list values. |
| `pkg/config/compiler_policy_match_address_set_3149_test.go` | policy address resolution | negative | 1-5 | Dangling and empty address sets fail closed across policy scopes. |
| `pkg/config/compiler_policy_match_application_3144_test.go` | policy application resolution | negative | 1-5 | Undefined/empty application references reject; valid built-ins and sets survive. |
| `pkg/config/compiler_policy_match_ssot_4121_test.go` | policy AST convergence | negative | 1-5 | Flat, hierarchical, repeated, bracket, and dual-slot match forms converge. |
| `pkg/config/compiler_policy_missing_match.go` | policy validation | negative | 1-5 | Zone/global policies require source, destination, and application criteria. |
| `pkg/config/compiler_policy_missing_match_3044_test.go` | policy validation tests | negative | 1-5 | Required match dimensions reject strictly and downgrade deterministically. |
| `pkg/config/compiler_policy_term_multimatch_2642_test.go` | routing policy terms | negative | 1-5 | Repeated community/prefix-list/as-path values accumulate without truncation. |
| `pkg/config/compiler_policy_then.go` | security policy actions | negative | 1-5 | Terminal actions, modifiers, orphan tokens, and AST multiplicity stay fail closed. |
| `pkg/config/compiler_policy_then_3114_test.go` | permit action grammar | negative | 1-5 | Unsupported `then permit` children reject without rejecting bare permit. |
| `pkg/config/compiler_policy_then_3115_test.go` | reject action grammar | negative | 1-5 | Unsupported `then reject` children reject without rejecting bare reject. |
| `pkg/config/compiler_policy_then_deny_3141_test.go` | deny action grammar | negative | 1-5 | Deny logging is retained and unknown deny modifiers cannot disappear. |
| `pkg/config/compiler_policy_then_deny_3374_test.go` | deny action grammar | negative | 1-5 | Orphan log sub-tokens reject; explicit log subtrees remain functional. |
| `pkg/config/compiler_policy_then_twonode_3377_test.go` | action AST convergence | negative | 1-5 | Duplicate terminal nodes cannot bypass permit/reject/deny validation. |
| `pkg/config/compiler_prefix_list_bracket_3996_test.go` | prefix-list parsing | negative | 1-5 | Bracket members retain all prefixes and modifiers. |
| `pkg/config/compiler_prefix_list_hier_leaf_3843_test.go` | prefix-list parsing | negative | 1-5 | Hierarchical leaf/block forms preserve members and modifiers. |
| `pkg/config/compiler_prefix_list_merge_2641_test.go` | prefix-list merging | negative | 1-5 | Repeated named prefix-list blocks merge rather than replace. |
| `pkg/config/compiler_prefix_list_ref_2506_test.go` | filter cross-reference | negative | 1-5 | Undefined source/destination prefix lists reject or warn safely. |
| `pkg/config/compiler_preid_default_policy_log_2509_test.go` | pre-ID policy observability | negative | 1-5 | Accepted-only logging is surfaced and not misrepresented as enforced. |
| `pkg/config/compiler_prewalk.go` | compiler AST prewalk | negative | 1-5 | Raw-token, duplicate, and cross-node gates traverse every expanded root in stable order. |
| `pkg/config/compiler_protocols.go` | dynamic routing compiler | A3-b3-F001 | 1-5 | Each BGP neighbor must own inherited import/export slice storage. |
| `pkg/config/compiler_qualified_nexthop_3871_test.go` | static routing | negative | 1-5 | Qualified next-hop preference/metric/interface remain per next hop. |
| `pkg/config/compiler_retired_dataplane_knobs_test.go` | dataplane compatibility | negative | 1-5 | Retired knobs are accepted only with explicit operator advisories. |
| `pkg/config/compiler_ribgroup_ref_2226_test.go` | rib-group validation | negative | 1-5 | Import-rib references resolve to real tables and fail closed otherwise. |
| `pkg/config/compiler_rip_multivalue_3904_test.go` | RIP compiler | negative | 1-5 | Repeated/bracketed RIP interfaces and redistribution values are not truncated. |
| `pkg/config/compiler_route_filter_range_2525_test.go` | route-filter validation | negative | 1-5 | Unsupported `through` and malformed length ranges cannot widen policy. |
| `pkg/config/compiler_routing.go` | static/policy routing compiler | A3-b3-F002 | 1-5 | Every schema-advertised static route action must survive into typed/runtime state. |
| `pkg/config/compiler_routing_instance_interface_3904_test.go` | routing instances | negative | 1-5 | Multi-value interface membership converges across syntax forms. |
| `pkg/config/compiler_routing_rules_test.go` | routing rule validation | negative | 1-5 | Rule ordering, family, and table references stay deterministic and bounded. |
| `pkg/config/compiler_rpm_http_scheme_2495_test.go` | RPM validation tests | negative (A3-b3-F004 gap) | 1-5 | Scheme cases are covered, but hostless absolute URLs are absent. |
| `pkg/config/compiler_rpm_linklocal_zone_2494_test.go` | RPM validation | negative | 1-5 | IPv6 link-local targets require an unambiguous egress scope. |
| `pkg/config/compiler_rpm_routing_instance_2496_test.go` | RPM validation | negative | 1-5 | Probe routing-instance references must resolve. |
| `pkg/config/compiler_rpm_scoped_hostname_2493_test.go` | RPM DNS scoping | negative | 1-5 | Scoped hostnames remain valid after VRF-aware resolver support. |
| `pkg/config/compiler_rpm_source_2492_test.go` | RPM source binding | negative | 1-5 | Malformed or family-mismatched source addresses cannot fall back to wildcard bind. |
| `pkg/config/compiler_sampling_source_address_test.go` | sampling compiler | negative | 1-5 | Sampling source-address forms preserve family and value. |
| `pkg/config/compiler_schedulers_3849_test.go` | scheduler compiler | negative | 1-5 | Scheduler window forms compile consistently and empty windows fail closed. |

### Security, services, system, and tail gates

| Path | Module/subsystem | Result | Dims | Invariant checked |
|---|---|---|---|---|
| `pkg/config/compiler_security.go` | security dispatcher | negative | 1-5 | Repeated security roots aggregate without losing NAT/policy/screen state. |
| `pkg/config/compiler_security_addressbook.go` | address-book compiler | negative | 1-5 | Addresses, sets, dynamic names, and zone/global books preserve identity and membership. |
| `pkg/config/compiler_security_alg.go` | ALG compiler | negative | 1-5 | Supported flags compile; unsupported protocols remain visible as advisories. |
| `pkg/config/compiler_security_bracket_list_3703_test.go` | security list parsing | negative | 1-5 | Bracket lists retain all NAT/policy/address values across AST shapes. |
| `pkg/config/compiler_security_flow.go` | flow compiler | negative | 1-5 | Flow aging, MSS, trace, and TCP-session values cannot silently coerce unsafe state. |
| `pkg/config/compiler_security_log.go` | security logging compiler | negative | 1-5 | Streams/profiles/formats preserve references and accepted-only semantics. |
| `pkg/config/compiler_security_policy.go` | security policy compiler | negative | 1-5 | Policy ordering, matches, actions, global scope, and defaults stay explicit. |
| `pkg/config/compiler_security_screen.go` | screen compiler | negative | 1-5 | Unknown/nonnumeric screen leaves are recorded for strict rejection. |
| `pkg/config/compiler_security_zones.go` | zone compiler | negative | 1-5 | Interface membership and host-inbound tokens accumulate without cross-zone leakage. |
| `pkg/config/compiler_services.go` | services/RPM compiler | A3-b3-F004 | 1-5 | An absolute RPM HTTP target must have both an allowed scheme and a host. |
| `pkg/config/compiler_signed_port_3606_test.go` | port parsing | negative | 1-5 | Signed/noncanonical ports cannot wrap or canonicalize silently. |
| `pkg/config/compiler_snmp_trapgroup_2990_test.go` | SNMP compiler tests | negative (A3-b3-F003 gap) | 1-5 | Trap-group accumulation is covered; duplicate community merge is not. |
| `pkg/config/compiler_ssh_hardening_4305_test.go` | SSH compatibility | negative | 1-5 | Enforced and accepted-only hardening knobs are distinguished. |
| `pkg/config/compiler_static_nexthop_list_3872_test.go` | static routing tests | negative (A3-b3-F002 gap) | 1-5 | ECMP next-hop lists and empty-delete behavior are covered, not `reject`. |
| `pkg/config/compiler_static_route_inline_iface_3881_test.go` | static routing tests | negative (A3-b3-F002 gap) | 1-5 | Inline interface qualifiers survive, but no reject-action assertion exists. |
| `pkg/config/compiler_surface_a_ddns_test.go` | DDNS compiler | negative | 1-5 | Provider, source, hostname, and family fields retain secrets and validation state. |
| `pkg/config/compiler_syslog_hostmods_4303_test.go` | syslog compiler | negative | 1-5 | Host modifiers are parsed and surfaced rather than silently discarded. |
| `pkg/config/compiler_system.go` | system/SNMP compiler | A3-b3-F003 | 1-5 | Repeated same-name SNMP communities must not erase client restrictions. |
| `pkg/config/compiler_tailgates.go` | compiler tail orchestration | negative | 1-5 | Strict first-error and tolerant warning order remain stable through final gates. |
| `pkg/config/compiler_tcp_mss_range_test.go` | flow MSS validation | negative | 1-5 | MSS values remain range-checked across families and syntax forms. |
| `pkg/config/compiler_tcp_session_seqcheck_test.go` | TCP session compatibility | negative | 1-5 | Sequence-check knobs remain explicit accepted-only state. |
| `pkg/config/compiler_test.go` | compiler baseline | negative | 1-5 | Core compile/default/error behavior remains deterministic. |
| `pkg/config/compiler_three_color_default_4535_test.go` | policer compiler | negative | 1-5 | Three-color defaults cannot produce an unsafe zero/undefined action. |
| `pkg/config/compiler_undefined_ref_2217_test.go` | cross-reference gates | negative | 1-5 | Undefined policer, routing-instance, and application-set references reject. |
| `pkg/config/compiler_uniformgates.go` | fail-open gate orchestration | negative | 1-5 | Gate ordering, strict/tolerant symmetry, and warning accumulation remain explicit. |

### Strict validation and compiler gates

| Path | Module/subsystem | Result | Dims | Invariant checked |
|---|---|---|---|---|
| `pkg/config/compiler_validate_scheduler_no_window_3860_test.go` | scheduler advisory | negative | 1-5 | Missing effective windows warn while runtime remains inactive. |
| `pkg/config/compiler_validate_strict.go` | strict validation core | negative | 1-5 | Shared structural and reference gates reject before unsafe runtime publication. |
| `pkg/config/compiler_validate_strict_application.go` | application validation | negative | 1-5 | Protocol/port/syntax/structure and nested sets cannot become wildcard matches. |
| `pkg/config/compiler_validate_strict_chassis.go` | chassis validation | negative | 1-5 | Redundancy-group count and IDs fit heartbeat wire widths. |
| `pkg/config/compiler_validate_strict_chassis_4434_test.go` | chassis validation tests | negative | 1-5 | Boundary and tolerant-path behavior match the heartbeat contract. |
| `pkg/config/compiler_validate_strict_cos.go` | CoS validation | negative | 1-5 | Queue, loss-priority, map, and numeric values stay representable. |
| `pkg/config/compiler_validate_strict_filter.go` | firewall filter validation | negative | 1-5 | Unknown, contradictory, or unrepresentable matches/actions cannot widen terms. |
| `pkg/config/compiler_validate_strict_ipsec.go` | IKE/IPsec validation | negative | 1-5 | References, crypto protocols, auth values, and unsupported manual SAs fail closed. |
| `pkg/config/compiler_validate_strict_nat.go` | NAT validation | negative | 1-5 | Address/application/protocol/port/pool errors cannot wildcard or wrap translation. |
| `pkg/config/compiler_validate_strict_observability.go` | observability validation | negative | 1-5 | Log, flow, feed, sampling, and DDNS references remain runtime-resolvable. |
| `pkg/config/compiler_validate_strict_policy.go` | policy validation | negative | 1-5 | Zone/action/log/name/address/community invariants reject ambiguous policy state. |
| `pkg/config/compiler_validate_strict_reth_vrrp.go` | RETH/VRRP validation | negative | 1-5 | Derived VRID remains within the one-byte protocol range. |
| `pkg/config/compiler_validate_strict_reth_vrrp_4826_test.go` | RETH/VRRP tests | negative | 1-5 | Derived-ID boundaries reject strictly and warn tolerantly. |
| `pkg/config/compiler_validate_strict_routing.go` | routing validation | negative | 1-5 | Route-map, ASN, router-ID, auth, route-filter, and rib references stay loadable. |
| `pkg/config/compiler_validate_strict_screen.go` | screen validation | negative | 1-5 | Missing profiles and unsupported/nonnumeric options cannot disable screening silently. |
| `pkg/config/compiler_validate_strict_vrrp.go` | VRRP validation | negative | 1-5 | Explicit VRID remains in RFC 5798 range. |
| `pkg/config/compiler_validate_strict_vrrp_4573_test.go` | VRRP ID tests | negative | 1-5 | Packed and structured VRID forms share strict/tolerant bounds. |
| `pkg/config/compiler_validate_strict_vrrp_priority.go` | VRRP priority validation | negative | 1-5 | Priority cannot narrow to a reserved/wrong wire value. |
| `pkg/config/compiler_validate_strict_vrrp_priority_5184_test.go` | VRRP priority tests | negative | 1-5 | Packed priority bypasses are closed without rejecting valid boundaries. |
| `pkg/config/compiler_validate_strict_zones.go` | zone validation | negative | 1-5 | Reserved names, count, interfaces, tokens, and references preserve zone isolation. |
| `pkg/config/compiler_validate_vrf_overlap.go` | VRF overlap advisory | negative | 1-5 | Cross-VRF session-key collisions are surfaced deterministically. |
| `pkg/config/compiler_validate_vrf_overlap_2387_test.go` | VRF overlap tests | negative | 1-5 | Distinct/same VRF and family overlap cases warn without false rejection. |
| `pkg/config/compiler_validate_warn.go` | advisory validation | negative | 1-5 | Accepted-only and runtime-gap warnings are read-only, stable, and comprehensive. |
| `pkg/config/compiler_validate_warn_nil_3494_test.go` | tolerant validation tests | negative | 1-5 | Nil tolerated entries cannot panic warning generation. |
| `pkg/config/compiler_validate_wireguard.go` | WireGuard validation | negative | 1-5 | Keys, ports, endpoints, peer uniqueness, and AllowedIPs hydrate safely. |
| `pkg/config/compiler_zone_interfaces_bracket_5248_test.go` | zone list parsing | negative | 1-5 | Bracketed interface members retain every interface and validate each one. |

### AST edits, duplicate gates, DHCP/DDNS, and event options

| Path | Module/subsystem | Result | Dims | Invariant checked |
|---|---|---|---|---|
| `pkg/config/completion_prefix_test.go` | CLI completion | negative | 1-5 | Prefix completion remains bounded and context-correct. |
| `pkg/config/cos_unknown_codepoint_5194_test.go` | CoS parser | negative | 1-5 | Unknown code points remain visible and cannot silently map to defaults. |
| `pkg/config/ddns_porthost_4589_test.go` | DDNS URL parsing | negative | 1-5 | Hostless/port-only DDNS authorities reject rather than no-op. |
| `pkg/config/ddns_provider_string_test.go` | DDNS provider parsing | negative | 1-5 | Provider strings and secrets survive AST/compiler conversion. |
| `pkg/config/deactivate_multi_leaf_3975_test.go` | AST deactivate | negative | 1-5 | Deactivation targets only selected multi-leaf members across forms. |
| `pkg/config/delete_multi_leaf_member_3846_test.go` | AST delete | negative | 1-5 | Deleting one list member preserves siblings and canonical structure. |
| `pkg/config/delete_static_nexthop_3872_test.go` | AST delete/static routes | negative | 1-5 | Next-hop deletion cannot synthesize a blackhole. |
| `pkg/config/deterministic_nat_advisory_4559_test.go` | NAT advisory | negative | 1-5 | Enforced and deferred deterministic NAT modes warn accurately. |
| `pkg/config/deterministic_nat_flatset_3864_test.go` | NAT parser | negative | 1-5 | Flat deterministic NAT parameters retain block and host values. |
| `pkg/config/dhcp_expired_leases_test.go` | DHCP lease compiler | negative | 1-5 | Expired leases do not resurrect or influence compiled state. |
| `pkg/config/dhcp_static_binding_test.go` | DHCP static bindings | negative | 1-5 | MAC/address uniqueness, subnet, family, and lenient behavior are enforced. |
| `pkg/config/dpd_typed_value_4878_test.go` | IKE DPD parsing | negative | 1-5 | DPD values remain typed and range-bounded. |
| `pkg/config/dual_ast_differential_test.go` | parser/compiler differential | negative | 1-5 | Flat-set and hierarchical ASTs compile to equivalent typed configuration. |
| `pkg/config/dup_host_local_address.go` | host-inbound validation | negative | 1-5 | Same local address with differing zone admission is rejected deterministically. |
| `pkg/config/dup_host_local_address_3718_test.go` | host-inbound tests | negative | 1-5 | IPv4/IPv6/VRRP/override ambiguity and safe equal-policy cases are covered. |
| `pkg/config/dup_named_blocks.go` | duplicate-block validation | negative (A3-b3-F003 scope gap) | 1-5 | Existing gate covers groups/interfaces/screens, not SNMP communities. |
| `pkg/config/dup_named_blocks_5180_test.go` | duplicate-block tests | negative (A3-b3-F003 gap) | 1-5 | Covered named-block scopes reject; SNMP community is absent. |
| `pkg/config/dynamic_address_feed_dup_name_4913_test.go` | dynamic feeds | negative | 1-5 | Effective feed names are globally unique without worker leakage. |
| `pkg/config/dynamic_address_interval_4879_test.go` | dynamic feeds | negative | 1-5 | Update/hold intervals cannot silently coerce invalid strings. |
| `pkg/config/event_options_4423_test.go` | event-options compiler | negative | 1-5 | Event lists, actions, and DDNS fields retain multi-value semantics. |
| `pkg/config/event_options_match.go` | event match validation | negative | 1-5 | Event scope, field names, expression shape, and RE2 patterns stay fail closed. |
| `pkg/config/event_options_match_test.go` | event match tests | negative | 1-5 | Runtime/validator field SSOT and malformed/scope/regex cases are covered. |
| `pkg/config/event_options_within.go` | event temporal validation | negative | 1-5 | Seconds/count/mutual-exclusion errors cannot become unconditional triggers. |
| `pkg/config/event_options_within_3751_test.go` | event temporal tests | negative | 1-5 | Flat/hierarchical strict and tolerant temporal gates converge. |
| `pkg/config/fable167_advisory_test.go` | compatibility advisories | negative | 1-5 | Accepted-only feature warnings are emitted once and remain deterministic. |
| `pkg/config/fbf_fixture_test.go` | filter-based forwarding fixture | negative | 1-5 | FBF fixture compiles into the intended routing-instance action. |

### Firewall filters and flow tracing

| Path | Module/subsystem | Result | Dims | Invariant checked |
|---|---|---|---|---|
| `pkg/config/filter_match_resolve.go` | filter symbolic resolver | negative | 1-5 | ICMP and port symbols resolve to numeric SSOT values or remain rejectable. |
| `pkg/config/filter_protocol_rust_mirror_3393_test.go` | protocol SSOT | negative | 1-5 | Go protocol acceptance stays aligned with Rust resolution. |
| `pkg/config/firewall_address_except_matchany_4338_test.go` | filter address inversion | negative | 1-5 | Match-any plus except retains negation rather than becoming wildcard accept. |
| `pkg/config/firewall_address_except_mutex_3359_test.go` | filter validation | negative | 1-5 | Positive and except address constraints cannot coexist ambiguously. |
| `pkg/config/firewall_address_literal_3433_test.go` | filter validation | negative | 1-5 | Literal addresses must parse and match the filter family. |
| `pkg/config/firewall_crossfield_3723_test.go` | filter validation | negative | 1-5 | Protocol/port/flags/ICMP combinations must be satisfiable. |
| `pkg/config/firewall_dscp_drift_3309_test.go` | DSCP SSOT | negative | 1-5 | Named DSCP catalog and accepted values do not drift. |
| `pkg/config/firewall_dscp_range_3309_test.go` | DSCP validation | negative | 1-5 | Match and rewrite values remain within 0..63 or known names. |
| `pkg/config/firewall_filter_expand.go` | filter expansion accounting | negative | 1-5 | Counter stride equals the full address/prefix/port cross-product without overflow drift. |
| `pkg/config/firewall_filter_regressions_4422_test.go` | filter regressions | negative | 1-5 | Reversed ranges and parser-shape regressions remain rejected. |
| `pkg/config/firewall_from_unenforced_3307_test.go` | filter validation | negative | 1-5 | Unsupported `from` leaves cannot disappear and broaden a term. |
| `pkg/config/firewall_multivalue_2545_test.go` | filter parsing | negative | 1-5 | Repeated/bracketed protocols, ports, and addresses retain all values. |
| `pkg/config/firewall_port_except_2622_test.go` | filter port inversion | negative | 1-5 | Port-except compiles with preserved polarity. |
| `pkg/config/firewall_port_except_mutex_3297_test.go` | filter validation | negative | 1-5 | Positive and except ports cannot resolve by silent precedence. |
| `pkg/config/firewall_ri_conflict_3308_test.go` | FBF validation | negative | 1-5 | Routing-instance and discard/reject cannot coexist. |
| `pkg/config/firewall_ri_output_direction_3432_test.go` | FBF validation | negative | 1-5 | Routing-instance steering rejects on unsupported output attachment. |
| `pkg/config/firewall_symbolic_match_3205_test.go` | symbolic filter matches | negative | 1-5 | Known symbols resolve and unknown symbols fail closed on strict/tolerant paths. |
| `pkg/config/firewall_terminal_conflict_4375_test.go` | filter action validation | negative | 1-5 | Multiple distinct terminating actions cannot become last-writer-wins. |
| `pkg/config/flow_aging_3440_test.go` | flow aging validation | negative | 1-5 | Watermark order and unknown aging leaves reject; accepted-only state warns. |
| `pkg/config/flow_traceoptions_file_3420_test.go` | flow trace compiler | negative | 1-5 | File rotation/count/size values remain typed and bounded. |
| `pkg/config/flow_traceoptions_filter_3422_test.go` | flow trace compiler | negative | 1-5 | Trace filter fields and lists retain every constraint without wildcarding. |

### A3-b4: Go configuration compiler, schema and CLI grammar (135 files)

Batch-list SHA-256: `4477225b3a51622d94bc62c558438bdd697cb4f1f0b0ef5f4e72387446724b5c`.

### Parser, lexer, AST, and text hygiene

Dimensions checked: malformed input must fail closed without truncation; parser memory, recursion, and error recovery must remain bounded; AST helpers must avoid aliasing and nil leaks; hierarchical and flat Junos grammar must agree; control-plane parsing must stay linear and off the packet path; parser, formatter, and sanitizer ownership must remain modular; negative and round-trip tests must exercise malformed delimiters and termination.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/freetext.go` | Free-text/annotation hygiene | negative | Strict rejection and lenient sanitization prevent control/comment injection without mutating the strict candidate. |
| `pkg/config/freetext_test.go` | Free-text tests | negative | Newlines, controls, comment delimiters, round trips, and lenient sanitization are covered. |
| `pkg/config/inactive.go` | Inactive AST pruning | negative | Pruning is clone-safe, deterministic, nil-safe, and bounded by parser depth. |
| `pkg/config/inactive_test.go` | Inactive grammar/tests | negative | Parser, formats, groups, schema, compile, HA, and non-mutation behavior are exercised. |
| `pkg/config/inline_inactive_4335_test.go` | Inline inactive grammar | negative | Inline markers are lifted without changing active leaf semantics. |
| `pkg/config/json_repeated_leaf_5194_test.go` | JSON AST formatting | negative | Repeated leaves remain arrays instead of silently overwriting values. |
| `pkg/config/lexer.go` | Lexer/tokenization | A3-b4-F001, A3-b4-F002 | Token errors must be bounded and structural bracket syntax must not disappear without validation. |
| `pkg/config/parser.go` | Hierarchical/flat parser | A3-b4-F001, A3-b4-F006 | Error collection must be bounded and only EOF may permit an omitted terminator. |
| `pkg/config/parser_ast_test.go` | Parser/compiler integration | A3-b4-F005 | Broad round-trip and compiler coverage exists, but shared-UMEM tests cover only a canonical mode. |
| `pkg/config/parser_bracket_list_2419_test.go` | Bracket-list grammar | negative | Valid flat lists collapse equivalently to hierarchical lists and compile all members. |
| `pkg/config/parser_recursion_dos_hb164_test.go` | Parser DoS regression | A3-b4-F001, A3-b4-F002 | Stack/depth tests expose brackets-only acceptance but do not bound lexical error accumulation. |
| `pkg/config/parser_semicolon_5194_test.go` | Flat command terminators | A3-b4-F006 | Flat commands reject trailing statements, but hierarchical missing-semicolon behavior is untested. |
| `pkg/config/parser_stray_brace_4862_test.go` | Brace error recovery | negative | Top-level stray braces are consumed, reported, and do not truncate following statements. |
| `pkg/config/quoted_inactive_4348_test.go` | Quoted marker grammar | negative | Quoted `inactive:` text remains data while bare markers retain control semantics. |
| `pkg/config/quotekey_roundtrip_3854_test.go` | Quoting/round trip | negative | Lexer and formatter quoting are symmetric and idempotent. |

### Host-inbound and junos-host projection

Dimensions checked: coarse and fine host-bound enforcement must fail closed and agree across Go nft and Rust AF_XDP paths; nil maps and per-interface unions must be safe and deterministic; compile-time projection must not add packet-path allocation; vSRX token/family semantics and lifeline exceptions must be explicit; token, projection, view, parity, and negative tests must cover strict and tolerant paths.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/host_inbound_dup_block_4544_test.go` | Duplicate host-inbound blocks | negative | Repeated zone/interface blocks merge and deduplicate without dropping admission tokens. |
| `pkg/config/host_inbound_effective_3720_test.go` | Effective per-interface admission | negative | Logical units inherit and union physical overrides consistently. |
| `pkg/config/host_inbound_fulladmit_warn_3226_test.go` | Full-admit advisory | negative | `all` and per-interface full-admit posture is surfaced without changing enforcement. |
| `pkg/config/host_inbound_managed_routing_mismatch_4455_test.go` | Routing/host-inbound advisory | negative | Managed routing protocols missing from admission produce deterministic warnings. |
| `pkg/config/host_inbound_match_3627_test.go` | Host-inbound match catalog | negative | Service/protocol tuples, families, and reject markers match the declared catalog. |
| `pkg/config/host_inbound_multicast.go` | Multicast advisory catalog | negative | Known multicast groups are deterministic; the documented packet-wide enforcement gap is not silently represented as enforcement. |
| `pkg/config/host_inbound_multicast_warn_4455_test.go` | Multicast warning tests | negative | `all`, overrides, unicast negatives, and catalog shape are covered. |
| `pkg/config/host_inbound_per_iface_3362_test.go` | Per-interface token grammar | negative | Per-interface tokens receive the same strict known-token gate as zone-level tokens. |
| `pkg/config/host_inbound_rust_parity_test.go` | Go/Rust token parity | negative | Known token and family sets are mechanically compared across languages. |
| `pkg/config/host_inbound_tokens.go` | Host-inbound token SSOT | A3-b4-F003 | Tolerant wrong-case normalization promised by the SSOT must also hold in fine-policy projection. |
| `pkg/config/host_inbound_tokens_test.go` | Token validation tests | A3-b4-F003 | Strict/lenient and known/unknown cases are covered, but tolerant case plus fine projection is not. |
| `pkg/config/host_inbound_view.go` | Host-inbound presentation | negative | Display unions preserve authored data while accurately showing effective/default-deny posture. |
| `pkg/config/host_inbound_view_3654_test.go` | Host-inbound view tests | negative | Zone, override, effective, render, and deny-reason views remain deterministic. |
| `pkg/config/host_inbound_view_lifeline_3682_test.go` | Lifeline presentation tests | negative | Lifeline exclusions are visible on zone and interface surfaces. |
| `pkg/config/junos_host_deny.go` | Fine junos-host deny projection | A3-b4-F003 | Coarse IKE/ident exemptions must be derived from the same normalized token domain as runtime admission. |
| `pkg/config/junos_host_deny_test.go` | Fine projection tests | A3-b4-F003 | Tier composition and canonical exemption flags are covered; tolerant mixed-case tokens are absent. |
| `pkg/config/lifeline.go` | Host-inbound lifeline SSOT | negative | Config-derived management/fabric exemptions are deterministic; the broad legacy `fab*` question is already tracked and suppressed. |

### Domain compiler and integration suites

Dimensions checked: strict commit and tolerant load behavior must preserve fail-closed runtime semantics; pointer, range, truncation, and duplicate-node handling must be safe; HA-derived identifiers and outputs must be deterministic; vSRX references and defaults must be complete; compiler work stays off the packet hot path and avoids unbounded expansion; domain ownership and negative tests must cover both hierarchical and flat shapes.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/flow_traceoptions_size_3424_test.go` | Flow trace validation | negative | Invalid rotation products reject strictly and downgrade only on tolerant ingress. |
| `pkg/config/flowserver_template_ref_test.go` | Sampling template references | negative | Dangling v9/IPFIX templates reject without affecting template-free collectors. |
| `pkg/config/frr_clusterid_origin_4919_test.go` | BGP schema/compiler | negative | Cluster IDs and origins are range/enum checked with value-bearing diagnostics. |
| `pkg/config/global_policy_zone_scope_3680_test.go` | Global policy scoping | negative | Explicit wildcard and scoped zone lists do not over-include unrelated zones. |
| `pkg/config/ike_policy_chain_ref_test.go` | IKE reference chain | negative | Gateway-policy-proposal chains fail on active dangling links and tolerate orphan definitions. |
| `pkg/config/interface_parity_4308_test.go` | Interface parity knobs | negative | Accepted-but-inert interface features compile with explicit advisories. |
| `pkg/config/ipip_tunnel_dead_warn_4788_test.go` | IPIP liveness | negative | A configured but unusable tunnel emits an operator-visible warning. |
| `pkg/config/ipsec_dhgroup_test.go` | IPsec DH groups | negative | Phase 1/2 spelling variants normalize without admitting invalid groups. |
| `pkg/config/ipsec_proposal_ref_test.go` | IPsec proposal references | negative | Explicit proposal references reject dangling/missing leaves and downgrade leniently. |
| `pkg/config/lenient_fw_cos_4953_test.go` | Tolerant firewall/CoS gates | negative | Invalid strict values become warnings without silent widening on tolerant paths. |
| `pkg/config/log_profile_schema_test.go` | Security log profile grammar | negative | Flat and hierarchical log-profile forms are accepted. |
| `pkg/config/log_profile_test.go` | Security log profiles | negative | Stream references, inactive profiles, and lenient dangling behavior are checked. |
| `pkg/config/log_stream_config_3349_test.go` | Security log stream validation | A3-b4-F004 | Field/port/mode checks exist, but the valid severity vocabulary is incomplete. |
| `pkg/config/log_stream_tls_profile_3350_test.go` | Log stream TLS references | negative | Unsupported TLS profiles reject in both AST shapes and downgrade leniently. |
| `pkg/config/login_custom_class_4304_test.go` | Login class mapping | negative | Custom classes cannot silently gain privilege and inert permissions warn. |
| `pkg/config/login_password_test.go` | Login authentication | negative | Crypt hashes parse in both forms and missing authentication is visible. |
| `pkg/config/login_username_4895_test.go` | Login identity safety | negative | Username key validation blocks control and sudoers metacharacter injection. |
| `pkg/config/named_port_caseinsensitive_3372_test.go` | Application port resolution | negative | Mixed-case named ports resolve identically and alias tables remain aligned. |
| `pkg/config/nat_range_wrap_5194_test.go` | NAT address expansion | negative | Full-domain ranges terminate without integer wrap. |
| `pkg/config/natpool.go` | Source-NAT operational filter | negative | Unknown pools are distinct from empty/unparseable pools and matching fails closed. |
| `pkg/config/natpool_test.go` | NAT pool tests | negative | CIDRs, hosts, invalid entries, unknown pools, and membership are covered. |
| `pkg/config/parser_class_of_service_test.go` | CoS compiler integration | negative | Queue, rate, buffer, binding, fairness, strict-reference, and warning semantics are broadly exercised. |
| `pkg/config/parser_cluster_test.go` | Chassis cluster compiler | negative | Cluster defaults, ownership, fabric, fencing, monitoring, and node mapping remain deterministic. |
| `pkg/config/parser_fbf_test.go` | Filter-based forwarding | negative | Flat and hierarchical composition compile equivalently. |
| `pkg/config/parser_ipmonitoring_test.go` | IP monitoring compiler | negative | Probe actions, next hops, validation, and lease-key derivation are covered. |
| `pkg/config/parser_routing_test.go` | Routing compiler integration | negative | Routing protocols, routes, tunnels, bridges, references, and dual AST forms receive broad coverage. |
| `pkg/config/parser_rpm_pin_test.go` | RPM route pinning | negative | Probe route pins, table allocation, conflicts, and source/next-hop constraints are tested. |
| `pkg/config/parser_security_test.go` | Security compiler integration | negative | Policies, NAT, screens, IPsec, zones, applications, and strict validation are broadly exercised. |
| `pkg/config/parser_services_test.go` | Services compiler integration | negative | DHCP, DNS, flow, DDNS, monitoring, and service validation are covered. |
| `pkg/config/parser_system_test.go` | System compiler integration | negative | Login, syslog, services, platform, and management configuration paths are covered. |
| `pkg/config/policer_rate_validate_5299_test.go` | Policer rates | negative | Zero/negative/overflow rates reject while valid minimums compile. |
| `pkg/config/policy_community_ref_test.go` | Policy community references | negative | Community actions reject dangling names and honor definitions/lenient warnings. |
| `pkg/config/policy_from_multileaf_2689_test.go` | Policy multi-value matches | negative | Repeated and bracketed `from` leaves preserve all values. |
| `pkg/config/policy_log_action_3060_test.go` | Policy logging actions | negative | Bare logging rejects instead of becoming an ambiguous terminal behavior. |
| `pkg/config/policy_match_excluded_test.go` | Excluded address matching | negative | Exclusion flags, `any` normalization, typo rejection, and tolerant downgrade are covered. |
| `pkg/config/policy_rematch_advisory_test.go` | Policy rematch advisory | negative | Unsupported rematch modes are visible while the implemented bare form remains accepted. |
| `pkg/config/policy_reserved_redist_name_5116_test.go` | Reserved policy names | negative | Synthetic redistribution suffixes cannot collide with authored policies. |
| `pkg/config/policy_terminal_action_3043_test.go` | Policy terminal actions | negative | Missing/conflicting actions reject; tolerant defaults deny and diagnostics name scope. |
| `pkg/config/policy_zone_matrix_4422_test.go` | Policy zone/action matrix | negative | Action compilation remains independent across zone combinations. |
| `pkg/config/policy_zone_ref_test.go` | Policy zone references | negative | Undefined zones reject while special wildcard/junos-host tokens retain intended semantics. |
| `pkg/config/predefined.go` | Predefined applications/sets | negative | Resolution precedence, recursion depth, cycles, and nil application-set lookup fail closed. |
| `pkg/config/predefined_app_sets_4102_test.go` | Predefined set tests | negative | Built-in bundles resolve and user definitions preserve precedence. |
| `pkg/config/predefined_icmp_3020_test.go` | Predefined ICMP apps | negative | Ping applications constrain echo-request types rather than all ICMP. |
| `pkg/config/predefined_nil_appset_5179_test.go` | Nil app-set regression | negative | The already-tracked nil map-value panic remains closed by lookup validation. |
| `pkg/config/protocols_multileaf_2587_test.go` | Routing policy multi-values | negative | Export/import/community lists retain every repeated and hierarchical value. |
| `pkg/config/reserved_zone_name_3055_test.go` | Reserved zone identities | negative | Special selector names cannot be declared as real zones and lenient ingress warns. |
| `pkg/config/reth_show.go` | RETH operational projection | negative | Bondless RETH/member maps, units, addresses, and sort order are nil-safe and deterministic. |
| `pkg/config/ribgroup_leak_warn_3876_test.go` | RIB-group leak advisory | negative | Cross-VRF and non-enumerable leaks warn while safe connected-prefix cases do not. |
| `pkg/config/router_id_2980_test.go` | Routing router IDs | negative | OSPF/BGP/instance IDs reject malformed/non-IPv4 values and downgrade leniently. |
| `pkg/config/routing_adjacency_4285_test.go` | Routing adjacency leaves | negative | OSPF timers/priority and BGP local-address inheritance compile faithfully. |
| `pkg/config/routing_export_ref_test.go` | Routing policy references | negative | Protocol export/import surfaces reject undefined policy names consistently. |
| `pkg/config/routinginstanceid.go` | Stable VRF table IDs | negative | Hash IDs, collision validation, quarantine, group views, and HA tie-breaking are deterministic. |
| `pkg/config/routinginstanceid_test.go` | VRF table-ID tests | negative | Reserved band, sibling stability, collision gate, and quarantine are exercised. |
| `pkg/config/rpm_probe_dup_block_4820_test.go` | Duplicate RPM blocks | negative | Repeated probe blocks merge tests without overwriting siblings. |
| `pkg/config/sampling_input_rate_5244_test.go` | Sampling rate validation | negative | Negative sampling rates reject; zero and valid values retain documented meaning. |
| `pkg/config/sampling_instance_conflict_test.go` | Sampling instance conflicts | negative | Family/version conflicts reject deterministically and tolerant ingress warns. |

### Schema grammar, completion, and validators

Dimensions checked: typed leaves and closed-world subtrees must reject unknown or out-of-range values before lossy compilation; schema state is immutable after initialization and introduces no concurrency or packet-path work; numeric conversions must not truncate or overflow runtime wire types; Junos/vSRX grammar and completion must share one vocabulary; aspect files must remain modular; strict, lenient, hierarchical, flat, trailing-token, and completion tests must cover each gate.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/schema.go` | Schema root/metadata | negative | Grammar composition, groups mirroring, scalar/typed metadata, and immutable shared nodes remain coherent. |
| `pkg/config/schema_chassis.go` | Chassis schema | negative | Cluster numeric ranges, enums, interface hardware values, and deployed shapes match compiler contracts. |
| `pkg/config/schema_closedworld_ike_proposal_4313_test.go` | IKE closed-world tests | negative | Unknown proposal keywords/crypto reject while valid and lenient forms remain usable. |
| `pkg/config/schema_closedworld_ipsec_4313_test.go` | IPsec closed-world tests | negative | Selector, monitor, and DPD subtrees reject unknown leaves in all tested forms. |
| `pkg/config/schema_closedworld_ipsec_proposal_4313_test.go` | IPsec proposal closed-world tests | negative | Unknown crypto/keywords reject and accepted-only lifetime behavior stays visible. |
| `pkg/config/schema_closedworld_nat64_4313_test.go` | NAT64 closed-world tests | negative | Unknown NAT64 keys reject strictly and downgrade on tolerant load. |
| `pkg/config/schema_closedworld_nat_then_4313_test.go` | NAT action closed-world tests | negative | Destination-NAT action typos reject without incorrectly closing source-NAT grammar. |
| `pkg/config/schema_closedworld_natv6v4_4313_test.go` | NAT v6/v4 closed-world tests | negative | Unknown translation keys reject while valid and lenient paths remain covered. |
| `pkg/config/schema_complete.go` | Schema completion/resolution | negative | Prefix resolution and dynamic value completion are deterministic after caller sorting; ambiguous prefixes fail safely. |
| `pkg/config/schema_cos.go` | CoS/firewall schema | negative | Rate/buffer/priority/code-point domains and irregular tail grammars align with compiler ranges. |
| `pkg/config/schema_cos_buffer_temporal_4228_test.go` | Temporal buffer grammar | negative | Valid temporal values compile with inert advisories and malformed/zero values reject. |
| `pkg/config/schema_cos_hb166_test.go` | CoS extended schema | negative | Shaping, burst, codel, fairness, completion, and materialization warnings are covered. |
| `pkg/config/schema_cos_ieee8021_rewrite_4228_test.go` | 802.1 rewrite schema | negative | Rewrite code points and loss priority validate while accepted-only behavior warns. |
| `pkg/config/schema_desc_test.go` | Completion descriptions | negative | Every reachable schema node has operator-facing description metadata. |
| `pkg/config/schema_global_zone_list_4415_test.go` | Global policy zone list schema | negative | Multi-zone list syntax is accepted without truncation. |
| `pkg/config/schema_ike_enum_3896_test.go` | IKE enum schema | negative | IKE mode/version/NAT traversal enums reject unsupported values. |
| `pkg/config/schema_interfaces.go` | Interface schema | negative | Address-family, VLAN, VRRP, tunnel, DDNS, and unit numeric domains align with runtime types. |
| `pkg/config/schema_lldp_ttl_4596_test.go` | LLDP range schema | negative | Transmit interval and hold multiplier honor protocol bounds. |
| `pkg/config/schema_master_password_prf_4578_test.go` | Master-password PRF schema | negative | Keyword/value typos reject and every runtime-supported selector is accepted. |
| `pkg/config/schema_policy_then_3377_test.go` | Policy action schema | negative | Completion and flat grammar expose the same terminal actions the compiler implements. |
| `pkg/config/schema_policy_then_int_4688_test.go` | Policy integer actions | negative | Integer action values are bounded and errors identify the authored value. |
| `pkg/config/schema_route_preference_3771_test.go` | Route preference schema | negative | Administrative distance stays in the non-negative wire-representable range. |
| `pkg/config/schema_route_qnh_preference_3827_test.go` | Qualified next-hop preference | negative | Qualified preferences share the route preference gate and compile valid values. |
| `pkg/config/schema_routing.go` | Routing/services schema | negative | Route, protocol, RA, sampling, LLDP, and relay values match runtime widths and protocol bounds. |
| `pkg/config/schema_scheduler_name_3117_test.go` | Scheduler references/completion | negative | Zone/global policy scheduler names group correctly and complete in both scopes. |
| `pkg/config/schema_schedulers.go` | Scheduler schema | negative | Time/date identity grammar is typed and bounded without runtime mutation. |
| `pkg/config/schema_security.go` | Security/application schema | A3-b4-F004 | Security log streams advertise ten runtime severities but validate only three. |
| `pkg/config/schema_system.go` | System/services schema | A3-b4-F004, A3-b4-F005 | System syslog has the full severity SSOT, while shared-UMEM mode lacks an enum gate. |
| `pkg/config/schema_validate_2008_test.go` | Core typed-leaf integration | A3-b4-F004 | System syslog and stream transport are tested, but security-stream extended severities are absent. |
| `pkg/config/schema_validate_2497_test.go` | Router-advertisement schema | negative | Prefixes, PREF64, preference, RDNSS, MTU, and flat forms reject malformed families/ranges. |
| `pkg/config/schema_validate_2524_test.go` | Ring-entry validation | negative | Ring sizes are positive, bounded powers of two. |
| `pkg/config/schema_validate_3895_test.go` | RA lifetime width tests | negative | Router/PREF64/prefix lifetimes stay within wire maxima. |
| `pkg/config/schema_validate_4119_test.go` | RA zero-lifetime tests | negative | Explicit zero remains distinguishable from unset while oversized values reject. |
| `pkg/config/schema_validate_chassis_test.go` | Chassis schema integration | negative | Flat/hierarchical deployed shapes and packed bypass attempts are covered. |
| `pkg/config/schema_validate_cos_rate_percent_4228_test.go` | CoS percentage tails | negative | Percent/remainder/exact shapes, conflicts, speed resolution, and inert advisories are checked. |
| `pkg/config/schema_validate_ddns_hostname_2779_test.go` | DDNS hostname validation | negative | Silent rewrite and length-overflow hostnames reject. |
| `pkg/config/schema_validate_ddns_source_address_2780_test.go` | DDNS source address | negative | Non-IP source addresses fail before runtime use. |
| `pkg/config/schema_validate_firewall_test.go` | Firewall reference schema | negative | Forwarding-class references use candidate definitions and do not assume absent Junos defaults. |
| `pkg/config/schema_validate_flow_numwidth_test.go` | Flow/session numeric widths | negative | Export timeouts, session timeouts, rates, and ports stay within wire widths and completion parity. |
| `pkg/config/schema_validate_interfaces_test.go` | Interface schema integration | negative | Family/address/VRRP shapes, packed bypasses, and completion examples are tested. |
| `pkg/config/schema_validate_route_2448_test.go` | Static route schema | negative | Destination/next-hop syntax, families, zone IDs, interfaces, ribs, and flat forms fail closed. |
| `pkg/config/schema_validate_route_filter_test.go` | Route-filter schema | negative | Match forms reject malformed prefixes while preserving supported `upto` shape. |
| `pkg/config/schema_validate_routing_4285_test.go` | Routing adjacency schema | negative | All adjacency typed leaves are matrix-tested at boundaries. |
| `pkg/config/schema_validate_system_test.go` | System services schema | negative | Name-server, virtual-address, list, and deployed service shapes validate consistently. |
| `pkg/config/schema_validate_test.go` | Generic schema validators | negative | Rate/size/percent/enum/integer helpers, trailing modifiers, grouping, and non-mutation are covered. |
| `pkg/config/schema_validate_trailing_token_3332_test.go` | Scalar arity/trailing tokens | negative | Scalar leaves reject garbage while true multi/opaque/named containers remain accepted. |
| `pkg/config/schema_validators.go` | Leaf validators | negative | Integer, finite percent, duration, wire-width, identity, and PRF validators avoid overflow and silent defaults. |

### A3-b5: Go configuration compiler, schema and CLI grammar (75 files)

Batch-list SHA-256: `54e5b36b0ba663b6c87e6a2c8f300d94218708fa644748b9d317a7b30747f251`.

### Schema and value validation

Dimensions: Correctness/security/fail-open review covered validator acceptance sets, malformed values, AST shape handling, and strict versus tolerant behavior. Memory/concurrency/truncation/leak review found only bounded, immutable tree/value walks and no shared mutation. vSRX completeness was checked for Junos-compatible ranges and grammar represented here. Performance review found validation proportional to authored configuration, outside the packet path. Modularity/test-gap review checked schema-to-typed-validator dispatch and internal-node traversal; no non-duplicate defect survived.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/schema_validators_cos.go` | Schema / CoS | negative | CoS percentages, priorities, scheduler maps, and queue values reject malformed or out-of-range input without truncation. |
| `pkg/config/schema_validators_ddns.go` | Schema / DDNS | negative | DDNS names, durations, backoff values, and provider values preserve strict parse failures rather than collapsing to defaults. |
| `pkg/config/schema_validators_devicemap.go` | Schema / chassis device map | negative | PCI/MAC/device selectors are syntax-checked before typed compilation; no unbounded allocation or mutable global state. |
| `pkg/config/schema_validators_ipsec.go` | Schema / IPsec | negative | IPsec identities, proposals, lifetimes, and selectors enforce their enumerations/ranges and do not silently narrow. |
| `pkg/config/schema_validators_logging.go` | Schema / logging | negative | Logging facilities, severities, names, and path-like values are constrained before consumers receive them. |
| `pkg/config/schema_validators_network.go` | Schema / network | negative | IP/prefix/MAC/port/VLAN/MTU grammar rejects malformed and overflowing values; family checks remain explicit. |
| `pkg/config/schema_validators_routing.go` | Schema / routing | negative | ASNs, metrics, preferences, and routing identifiers retain bounds and parse errors. |
| `pkg/config/schema_validators_scheduler.go` | Schema / scheduler | negative | Scheduler/time expressions and numeric controls are bounded and validation-only, with no runtime timer ownership. |
| `pkg/config/schema_validators_system.go` | Schema / system | negative | Service ports, time/system values, names, and management enums reject invalid values before apply. |
| `pkg/config/schema_walk.go` | Schema walker | negative | Known schema nodes invoke value validators on every represented value while internal/container nodes do not invent leaf values; intentional open-world behavior was not misreported as a new defect. |
| `pkg/config/schema_walk_internal_test.go` | Schema walker tests | negative | Internal-node, child traversal, and validator error propagation regressions are covered; no panic/truncation gap found. |
| `pkg/config/value_type.go` | Schema value-type dispatch | negative | Enum, integer/range, address/prefix, and union dispatch returns errors consistently and performs no unsafe narrowing or shared mutation. |

### Security grammar, screens, NAT, and strict gates

Dimensions: Correctness/security/fail-open review traced screen flags and thresholds, policy zone sets, NAT grammar, TCP flags, reference gates, and warning-only contracts. Memory/concurrency/truncation/leak review found bounded compile-time slices/maps and no packet ownership in this module. vSRX completeness identified one surviving observability parity gap, A3-b5-F003. Performance review found all work commit-time or bounded show-time; no packet-path allocation was introduced here. Modularity/test-gap review found the screen inventory SSOT omits a profile-wide enforcement mode and that the strict-gate canary proves symbol calls, not reachability, but no unwired production gate was found.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/scoped_global_zoneset_4626_test.go` | Security policy scope | negative | Scoped-global from/to zone sets compile all members without first-value loss or cross-scope contamination. |
| `pkg/config/screen_alarm_without_drop_test.go` | Screen compiler tests | negative (A3-b5-F003 contract witness) | `alarm-without-drop` compiles, defaults false, and rejects trailing garbage; the resulting mode must remain observable. |
| `pkg/config/screen_inventory.go` | Screen inventory SSOT | A3-b5-F003 | Operational inventory must distinguish drop-on-trip profiles from profile-wide audit/log-only profiles. |
| `pkg/config/screen_numeric_strict_3317_test.go` | Screen numeric gates | negative | Malformed/zero/negative numeric leaves cannot silently disable or weaken checks. |
| `pkg/config/screen_profile_ref_test.go` | Screen references | negative | Undefined zone-to-screen references reject strictly and tolerant behavior remains diagnosed. |
| `pkg/config/screen_synflood_subthreshold_3315_test.go` | SYN-flood grammar | negative | Attack/source/destination thresholds remain independently parsed, bounded, and retained. |
| `pkg/config/screen_trailing_token_3332_test.go` | Screen grammar | negative | Childless flags reject extra tokens in both authored AST shapes. |
| `pkg/config/screen_unknown_strict_3318_test.go` | Screen strict validation | negative | Unknown screen leaves fail closed rather than disappearing during typed compilation. |
| `pkg/config/static_nat_mapped_port_2491_test.go` | Static NAT grammar | negative | Mapped-port parsing, family constraints, and forward/reverse port intent remain consistent. |
| `pkg/config/static_nat_source_address_3435_test.go` | Static NAT validation | negative | Unsupported source-address matching is diagnosed instead of silently changing translation scope. |
| `pkg/config/static_nat_zone_test.go` | Static NAT zone references | negative | Zone-qualified static NAT behavior and warning/reject contracts are explicit; no new fail-open path found. |
| `pkg/config/strict_gate_wiring_canary_test.go` | Compiler gate canary | negative | Candidate test weakness was examined, but all production gates had call sites; no concrete dead/unreachable strict gate survived review. |
| `pkg/config/tcp_flags.go` | Firewall TCP-flag parser | negative (duplicate-suppressed) | Even-count dangling negation is the already-recorded #4714 `!!` residual and was not re-reported. |
| `pkg/config/tcp_flags_test.go` | TCP-flag parser tests | negative | Required/forbidden masks, separators, unknown flags, and odd dangling negation are covered without integer truncation. |
| `pkg/config/tcp_session_advisory_test.go` | TCP session advisories | negative | Advisory-only unsupported knobs remain deterministic and do not masquerade as enforcement. |
| `pkg/config/time_zone_path_validate_5011_test.go` | System time-zone validation | negative | Traversal/path payloads cannot escape the zoneinfo root through authored time-zone values. |
| `pkg/config/vrf_overlap_budget_5194_test.go` | Routing-instance validation | negative | Prefix-overlap validation is bounded by an explicit budget and fails closed rather than exhausting commit resources. |
| `pkg/config/web_management_auth_4047_test.go` | Web management auth | negative | Enabling web management requires an authentication path and rejects unauthenticated service exposure. |

### Secrets, AST rendering, and system services

Dimensions: Correctness/security/fail-open review covered secret serialization, URL redaction, repeated leaves/blocks, scoped rendering, syslog grammar, and system string validation. Memory/concurrency/truncation/leak review found immutable formatting and bounded compile-time data; shared-UMEM audit parsing checks normalization collisions. vSRX completeness was checked for Junos repeated-stanza merge/display behavior. Performance review found no per-packet work and bounded formatting. Modularity/test-gap review found the shared URL sanitizer assumes paths are non-sensitive, yielding A3-b5-F002.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/secret.go` | Secret serialization / URL redaction | A3-b5-F002 | A URL field documented as credential-bearing must not reveal a credential merely because it is placed in the path. |
| `pkg/config/secret_test.go` | Secret tests | negative (test gap noted in A3-b5-F002) | JSON/YAML/string redaction and sentinel refusal are covered, but path-segment URL credentials are not. |
| `pkg/config/set_repeated_leaf_3984_test.go` | Set-path grammar | negative | Repeated multi-leaves accumulate while scalar leaves retain deterministic replacement semantics. |
| `pkg/config/shared_umem_audit_test.go` | Shared-UMEM audit parser | negative | Interface-name normalization collisions, malformed artifacts, and bounded membership are rejected. |
| `pkg/config/show_config_dup_context_4562_test.go` | Scoped configuration rendering | negative | Intermediate descent unions duplicate context blocks and does not truncate later siblings. |
| `pkg/config/show_config_repeated_keyword_3980_test.go` | Configuration rendering | negative | Terminal repeated-keyword rendering includes every sibling in hierarchical and display-set forms. |
| `pkg/config/sqm_cookbook_fixture_test.go` | SQM config fixture | negative | Cookbook grammar reaches the intended typed CoS model without hidden defaults or unsupported leaves. |
| `pkg/config/ssh_known_hosts_dup_block_4821_test.go` | SSH known-host compiler | negative | Duplicate hierarchical host blocks merge keys rather than replacing earlier trust anchors. |
| `pkg/config/syslog_logfile.go` | Syslog file grammar | negative | Size/count parsing uses explicit units and bounds; malformed suffixes do not silently truncate. |
| `pkg/config/syslog_logfile_4860_test.go` | Syslog file tests | negative | Unit, overflow, malformed, and boundary cases pin strict logfile rotation parsing. |
| `pkg/config/system_multileaf_test.go` | System multi-leaf compiler | negative | Repeated DNS/NTP/system leaves preserve all intended values and do not alias backing state. |
| `pkg/config/system_string_injection_4902_test.go` | System string validation | negative | Newline/control-token injection into generated system artifacts is rejected at commit. |

### SNMP source policy

Dimensions: Correctness/security/fail-open review traced authored `clients` entries through parsing, validation, precompilation, UDP source extraction, and the request authorization check. Memory/concurrency/truncation/leak review confirmed immutable precompiled prefix slices and allocation-free reads on the serving path. vSRX completeness checked longest-prefix and `restrict` semantics. Performance remains O(number of client prefixes) per SNMP request with no parsing on the compiled path. Modularity/test-gap review found no canonical duplicate/tie policy, yielding A3-b5-F001.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/snmp_clients.go` | SNMP client allowlist | A3-b5-F001 | Equal canonical prefixes with conflicting actions must not resolve by accidental authored order. |
| `pkg/config/snmp_clients_4289_test.go` | SNMP enforcement tests | negative (test gap noted in A3-b5-F001) | Basic allow, restrict, default-deny, IPv4/IPv6, and longest-prefix behavior are covered; equal-prefix conflicts are not. |
| `pkg/config/snmp_clients_4711_test.go` | SNMP prefix-cache tests | negative (test gap noted in A3-b5-F001) | Precompiled/fallback parity and malformed-entry handling are covered, but not same-length action ties. |
| `pkg/config/snmp_clients_4834_test.go` | SNMP strict validation tests | negative (test gap noted in A3-b5-F001) | Invalid prefixes and misspelled `restrict` reject/warn as intended; semantic duplicate conflicts remain unchecked. |

### Tunnel and typed configuration model

Dimensions: Correctness/security/fail-open review covered deep copies, tunnel publication, stable IDs, model stringers, WireGuard peer/identity constraints, XFRM names, and model field ownership. Memory/concurrency/truncation/leak review found immutable copied slices/maps and bounded compile-time hashing; no unsafe code. vSRX completeness checked GRE/WireGuard/XFRM and screen model parity, contributing contract evidence to A3-b5-F003. Performance review found no packet-path logic and stable-ID work linear in configured endpoints. Modularity/test-gap review found first-child stable-ID walks, but that root cause is already tracked as the #3562 duplicate-block class and was suppressed.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/tunnel_perunit_deepcopy_test.go` | Tunnel model copy | negative | Per-unit tunnel state deep-copies peers/prefix slices and cannot alias later compilation mutations. |
| `pkg/config/tunnelemit.go` | Tunnel publication selection | negative | Only complete/supported tunnel configurations enter publication and malformed partial state does not become transit. |
| `pkg/config/tunnelid.go` | Tunnel stable IDs | negative (duplicate-suppressed) | Duplicate-block first-child bypass is the existing #3562 root-cause class; runtime collision fallback remains deterministic. |
| `pkg/config/tunnelid_test.go` | Tunnel ID tests | negative | Stable hash vectors, collision handling, determinism, and bounds are covered for represented trees. |
| `pkg/config/types.go` | Core typed config | negative | Top-level maps/slices and interface-name normalization retain typed ownership without unsafe sharing. |
| `pkg/config/types_chassis.go` | Chassis model | negative | Chassis/device/redundancy fields retain widths and explicit optionality; no narrowing or mutable globals. |
| `pkg/config/types_cos.go` | CoS model | negative | Scheduler/queue values and copies preserve configured units and do not add packet-path work. |
| `pkg/config/types_interfaces.go` | Interface/tunnel model | negative | Unit, address, tunnel, peer, and interface fields preserve per-instance ownership and family information. |
| `pkg/config/types_routing.go` | Routing model | negative | Route/protocol fields retain explicit widths, families, and repeated values without hidden truncation. |
| `pkg/config/types_security.go` | Security/screen model | A3-b5-F003 (contract evidence) | The typed model marks `AlarmWithoutDrop` as profile-wide forwarding behavior that operational inventory must expose. |
| `pkg/config/types_system.go` | System/DDNS model | A3-b5-F002 | `DDNSProvider.String` promises URL credential safety but delegates to a sanitizer that preserves paths. |
| `pkg/config/types_test.go` | Typed model tests | negative | Stringers, copies, zero values, and representative model contracts expose no additional non-duplicate defect. |
| `pkg/config/wireguard_allowedips_malformed_5194_test.go` | WireGuard AllowedIPs validation | negative | Malformed prefixes reject rather than disappearing from cryptokey routing. |
| `pkg/config/wireguard_multipeer_test.go` | WireGuard compiler tests | negative | Multi-peer ownership, exact-prefix conflict, key/endpoint/local identity, family, and redaction invariants are comprehensively pinned. |
| `pkg/config/xfrmi.go` | XFRM interface naming | negative | XFRM IDs/names parse within bounds and direct alias collisions are rejected by the called strict contract. |
| `pkg/config/xfrmi_test.go` | XFRM naming tests | negative | Canonical names, invalid forms, ID bounds, and round trips are covered without integer overflow. |

### VRRP

Dimensions: Correctness/security/fail-open review covered authentication, hold time, track-interface shape/duplication, secrets, IPv6, and virtual-address subnet checks. Memory/concurrency/truncation/leak review found compile-time immutable state only. vSRX completeness was checked against represented VRRPv4/v6 and tracking grammar. Performance is bounded by configured groups/addresses and outside packet forwarding. Modularity/test-gap review found focused strict and lenient coverage with no surviving non-duplicate defect.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/vrrp_authentication_4288_test.go` | VRRP authentication | negative | Unsupported/false-security authentication settings reject strictly and remain diagnosed on tolerant load. |
| `pkg/config/vrrp_preempt_holdtime_test.go` | VRRP timing | negative | Hold-time grammar, range, and preempt coupling avoid silent defaults or overflow. |
| `pkg/config/vrrp_track_secret_5195_test.go` | VRRP track secrets | negative | Track-interface identity is redacted from warnings/errors where required without suppressing actionable shape diagnostics. |
| `pkg/config/vrrp_track_test.go` | VRRP tracking grammar | negative | Duplicate, nested/sibling, orphan cost, strict/lenient, and accumulation behavior are explicitly covered. |
| `pkg/config/vrrp_v6_test.go` | VRRP IPv6 | negative | IPv6 groups/addresses and family-specific constraints compile and validate without v4 coercion. |
| `pkg/config/vrrp_vaddr_subnet_3013_test.go` | VRRP address validation | negative | Virtual addresses must match interface family/subnet and malformed addresses fail closed. |

### Security zones and stable IDs

Dimensions: Correctness/security/fail-open review covered zone caps, duplicate-block merge, interface definition/membership, local qualification, stable IDs, and runtime collision quarantine. Memory/concurrency/truncation/leak review found bounded maps and immutable snapshots. vSRX completeness checked Junos merge/membership behavior. Performance is linear in configured zones/interfaces and outside packet lookup. Modularity/test-gap review found the same first-child duplicate-block root cause already represented by #3562, so it was suppressed rather than re-reported.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/config/zone_count_cap_test.go` | Zone resource cap | negative | Strict/tolerant zone-count bounds prevent unbounded snapshot/control-plane growth. |
| `pkg/config/zone_dup_block_4818_test.go` | Zone compiler merge | negative | Repeated hierarchical zone blocks merge all properties instead of replacing prior state. |
| `pkg/config/zone_interface_defined_4515_test.go` | Zone interface references | negative | Undefined interface membership rejects strictly and cannot create a policy-bearing phantom interface. |
| `pkg/config/zone_interface_membership_test.go` | Zone membership | negative | One interface cannot silently occupy conflicting zones; normalized names are compared consistently. |
| `pkg/config/zone_local_unqualify_3358_test.go` | Zone local addresses | negative | Qualified/unqualified interface names resolve without losing local-address ownership. |
| `pkg/config/zoneid.go` | Zone stable IDs | negative (duplicate-suppressed) | First-child collision prewalk is the known #3562 duplicate-block validator class; runtime quarantine remains fail closed. |
| `pkg/config/zoneid_test.go` | Zone ID tests | negative | Stable vectors, known collisions, deterministic allocation, and quarantine behavior are covered for represented trees. |

### A4-b1: Configuration persistence and crypto at rest (63 files)

Batch-list SHA-256: `afacd0b7b56943adeb0a156cbfd61a040eab44a2b622ff385be48e5b9e624978`.

Every assigned path appears exactly once in the ledger below. Dimension key: `C/S` is correctness, security, and fail-open behavior; `M/C/L` is memory safety, concurrency, truncation, and leaks; `Parity` is vSRX feature completeness; `Perf` is performance and latency; `Mod` is ownership and modularity; `Tests` records the exercised invariant or residual gap. `N/A` means the dimension is not applicable to this control-plane-only surface, not that it was skipped.

### Store API, transactions, validation, and locking

| Path | Module/subsystem | Result | Invariant and review dimensions |
|---|---|---|---|
| `pkg/configstore/activate_test.go` | candidate activation | negative | C/S: activation preserves active/candidate transaction boundaries; M/C/L: store lock and clone ownership avoid alias/race; Parity: Junos-style activate semantics covered; Perf: bounded tree work outside packet path; Mod: uses public Store API; Tests: activate, deactivate, and commit transitions exercised, no surviving gap. |
| `pkg/configstore/check.go` | commit check | negative | C/S: parse/compile failures are returned without promotion; M/C/L: bounded input and lock ownership checked; Parity: commit-check behavior matches intended CLI contract; Perf: compile is control-plane only; Mod: validation remains centralized in compiler; Tests: side-effect-free checking covered. |
| `pkg/configstore/check_test.go` | commit-check tests | negative | C/S: valid and invalid checks preserve candidate state; M/C/L: repeated checks expose no state leak; Parity: expected diagnostics covered; Perf: no hot-path concern; Mod: black-box Store coverage; Tests: no untested retained candidate found. |
| `pkg/configstore/cluster_readonly_3893_test.go` | HA read-only guard | negative | C/S: standby mutation fails closed; M/C/L: state guard is lock-protected; Parity: cluster role behavior covered; Perf: constant-time role check; Mod: role predicate is shared; Tests: mutating entry points covered. |
| `pkg/configstore/commit_description_cap_4891_test.go` | commit metadata | negative | C/S: description cap prevents oversized journal metadata; M/C/L: allocation bound covered; Parity: commit metadata behavior adequate; Perf: bounded formatting; Mod: cap enforced at Store boundary; Tests: boundary values covered. |
| `pkg/configstore/config_lock_holder_5059_test.go` | configuration lock ownership | negative (duplicate suppressed) | C/S: holder checks and known cross-surface omissions were traced; M/C/L: lock lease and ownership concurrency checked; Parity: exclusive configure semantics relevant; Perf: constant-time checks; Mod: holder identity should remain one shared policy; Tests: residual holder candidates match tracked `#5059`, so none retained. |
| `pkg/configstore/config_size_ceiling_hb164_test.go` | ingress size limits | `A4-b1-F007` | C/S: network/CLI ingress cap is correct but disk-load readers bypass it; M/C/L: per-input allocation is bounded only on ingress; Parity: N/A; Perf: parser protection covered; Mod: one advertised cap is not used by persistence loaders; Tests: ingress cases pass, startup file-size and aggregate-history cases are absent. |
| `pkg/configstore/equal_flow_worker_cap_test.go` | semantic validation | negative | C/S: equal-flow worker count is bounded before commit; M/C/L: integer and allocation bounds checked; Parity: feature validation covered; Perf: prevents oversized worker setup; Mod: compiler owns the constraint; Tests: cap edges covered. |
| `pkg/configstore/freetext_store_test.go` | hierarchical free-text loads | negative | C/S: load modes and parser errors remain transactional; M/C/L: input passes common size guard; Parity: Junos free-text workflow covered; Perf: control-plane parse only; Mod: Store delegates parsing; Tests: override/merge behavior exercised. |
| `pkg/configstore/inactive_test.go` | inactive statements | negative | C/S: inactive nodes do not publish active policy; M/C/L: clone/format paths preserve flags; Parity: Junos inactive semantics covered; Perf: no packet-path work; Mod: AST owns inactive state; Tests: load, compare, and commit behavior covered. |
| `pkg/configstore/nodeid_lenient_test.go` | node-aware lenient compile | negative | C/S: persisted and peer configs retain availability without bypassing runtime safety; M/C/L: no unsafe state ownership; Parity: node-specific HA expansion covered; Perf: boot/sync compile only; Mod: leniency remains compiler option driven; Tests: node-id fallback covered. |
| `pkg/configstore/ra_interval_4525_test.go` | router-advertisement validation | negative | C/S: interval floor and schema bounds refuted timer-overflow candidates; M/C/L: narrowing/overflow path checked; Parity: RA constraints covered; Perf: runtime interval stays bounded; Mod: schema/compiler own validation; Tests: low and valid boundaries covered. |
| `pkg/configstore/redaction_placeholder_4060_test.go` | secret redaction input | negative | C/S: literal redaction placeholder cannot silently replace a real secret; M/C/L: no secret-bearing buffer leak found; Parity: configuration edit semantics covered; Perf: negligible; Mod: Store validation is shared; Tests: rejection and preservation covered. |
| `pkg/configstore/store.go` | Store core and HA sync | `A4-b1-F001`, `A4-b1-F007` | C/S: promotion, HA convergence, and confirm-resolution ordering traced; M/C/L: mutex ownership is coherent, but disk readers/history lack an aggregate byte budget; Parity: commit and HA semantics reviewed; Perf: no packet hot path, startup memory is material; Mod: Store coordinates DB/history/journal; Tests: persist-failure crash ordering and disk-load budget are missing. |
| `pkg/configstore/store_command.go` | command mutation dispatcher | negative (duplicate suppressed) | C/S: command parsing and lock-holder enforcement traced; M/C/L: mutations occur under Store lock; Parity: set/delete/annotate semantics reviewed; Perf: bounded command work; Mod: dispatcher reuses AST operations; Tests: surviving holder concern is the tracked `#5059` root. |
| `pkg/configstore/store_format.go` | format and compare | negative | C/S: active/candidate formatting and rollback selection checked; M/C/L: returned strings own their data; Parity: show/compare behavior covered; Perf: full-tree format is expected control-plane work; Mod: formatting remains isolated; Tests: no surviving mismatch. |
| `pkg/configstore/store_lock.go` | configure lock and lease | negative | C/S: acquisition, holder, expiry, and release transitions checked; M/C/L: timer generation and mutex sequencing avoid stale callbacks; Parity: exclusive configuration semantics covered; Perf: no polling or hot contention; Mod: lock policy centralized; Tests: lease and ownership suites cover observed paths. |
| `pkg/configstore/store_lock_3979_test.go` | configure-lock regression tests | negative | C/S: lock-required mutation and release behavior fail closed; M/C/L: concurrent state remains serialized; Parity: lock workflow covered; Perf: constant-time; Mod: public Store boundary tested; Tests: no new root beyond tracked lock work. |
| `pkg/configstore/store_lock_lease_4476_test.go` | lock lease tests | negative | C/S: stale timers cannot evict a renewed holder; M/C/L: generation sequencing and callback races covered; Parity: lease semantics adequate; Perf: one timer per lease; Mod: timer logic contained; Tests: renewal/expiry cases covered. |
| `pkg/configstore/store_new_test.go` | Store construction | `A4-b1-F007` | C/S: DB failure is fatal and defaults are coherent; M/C/L: fixed history count is initialized but no byte budget accompanies it; Parity: N/A; Perf: startup allocation reviewed; Mod: dependencies are constructed centrally; Tests: constructor failures covered, maximum persisted-history footprint is not. |
| `pkg/configstore/store_test.go` | Store integration tests | negative | C/S: load/edit/commit/rollback baseline inspected; M/C/L: serialized test paths expose no additional race or alias; Parity: principal Junos workflows covered; Perf: no benchmark claim relied upon; Mod: public API integration coverage; Tests: retained edge cases are recorded against their owning files. |
| `pkg/configstore/typed_leaf_lenient_test.go` | tolerant typed-leaf load | negative | C/S: compatibility warnings do not silently activate unsafe values; M/C/L: conversion bounds checked; Parity: rolling-upgrade behavior covered; Perf: compile-time only; Mod: compiler option owns leniency; Tests: strict-versus-lenient cases covered. |

### Commit-confirmed, persistence, history, archive, and reset

| Path | Module/subsystem | Result | Invariant and review dimensions |
|---|---|---|---|
| `pkg/configstore/archive_rotate_enoent_4689_test.go` | archive rotation tests | `A4-b1-F008`, `A4-b1-F009` | C/S: concurrent ENOENT is tolerated, but retention ordering and worker admission remain unsafe; M/C/L: concurrent removals covered, unbounded goroutine/snapshot retention is not; Parity: archive-on-commit behavior relevant; Perf: slow storage backlog untested; Mod: archive helper has no owner worker; Tests: ENOENT seam does not cover clock rollback or blocked writes. |
| `pkg/configstore/atomic_load_5187_test.go` | atomic active snapshot | negative | C/S: active tree and metadata are read from one durable snapshot; M/C/L: rename/read race is covered; Parity: N/A; Perf: one file read; Mod: DB read owns framing; Tests: replacement race covered, semantic `null` is owned by `A4-b1-F003`. |
| `pkg/configstore/commit_confirm_demote_4378_test.go` | confirm on HA demotion | `A4-b1-F001` | C/S: demotion clears pending state, but no injected active-write failure plus crash is covered; M/C/L: timer generation race covered; Parity: HA role transition relevant; Perf: N/A; Mod: shared confirm clearer is reused; Tests: success path only. |
| `pkg/configstore/commit_confirm_pending_edit_4000_test.go` | pending-confirm edit semantics | `A4-b1-F001` | C/S: plain commit preserves staged edits and confirms; M/C/L: lock/timer ordering covered; Parity: Junos commit-confirmed semantics covered; Perf: N/A; Mod: shared transition path; Tests: does not test durable-state ordering on write failure. |
| `pkg/configstore/commit_confirmed_3861_test.go` | confirm plus HA sync | `A4-b1-F001` | C/S: sync invalidates stale rollback timer; M/C/L: fired callback generation guard covered; Parity: HA convergence semantics covered; Perf: N/A; Mod: SyncApply uses common clearer; Tests: no crash between confirm deletion and failed active replacement. |
| `pkg/configstore/commit_confirmed_maxrange_4868_test.go` | confirm duration bounds | negative | C/S: duration is range checked before timer conversion; M/C/L: overflow refuted; Parity: CLI/store duration contract covered; Perf: one timer; Mod: Store has defense in depth; Tests: min/max/out-of-range covered. |
| `pkg/configstore/commit_confirmed_persist_4577_test.go` | durable confirm recovery | `A4-b1-F001` | C/S: arm/restart/recover happy paths work; M/C/L: timer restoration checked; Parity: reboot-safe confirmation expected; Perf: one state file; Mod: DB owns record; Tests: recovery-state deletion following active-write failure is absent. |
| `pkg/configstore/confirm_delete_fsync_4864_test.go` | confirm unlink durability | `A4-b1-F001` | C/S: unlink plus parent fsync is correct when deletion should occur; M/C/L: no concurrency concern; Parity: reboot semantics covered; Perf: one fsync; Mod: DB primitive is sound; Tests: transition ordering, not unlink durability, is the retained defect. |
| `pkg/configstore/durability_3441_test.go` | rollback and archive durability | `A4-b1-F005`, `A4-b1-F009` | C/S: test explicitly preserves stale bytes under a shifted tombstone; M/C/L: atomic write seams covered; Parity: rollback numbering and archive history relevant; Perf: batched fsync reviewed; Mod: history-to-file mapping is implicit; Tests: restart after shifted tombstone and backward-clock retention are missing. |
| `pkg/configstore/factory_reset.go` | cryptographic erase | `A4-b1-F004` | C/S: key-first DB erase is durable, but the artifact inventory is directory-local and filename based; M/C/L: crash temp leaks remain; Parity: zeroize behavior relevant; Perf: one directory scan; Mod: primitive lacks archive ownership input/registry; Tests: external archives and hidden fsatomic remnants absent. |
| `pkg/configstore/factory_reset_4858_test.go` | reset completeness tests | `A4-b1-F004` | C/S: authoritative DB, local rollback, rescue, and journal are covered; M/C/L: no writer-race or hidden-temp case; Parity: zeroize outcome tested; Perf: N/A; Mod: finite seeded list mirrors implementation; Tests: does not seed default external archive directory or `.<base>.tmp-*`. |
| `pkg/configstore/factory_reset_durable_5197_test.go` | reset durability tests | `A4-b1-F004` | C/S: key-first and parent-fsync failures surface; M/C/L: interruption durability covered; Parity: zeroize durability expected; Perf: fsync cost accepted; Mod: seams isolate barriers; Tests: artifact discovery completeness remains untested. |
| `pkg/configstore/file_perms_4056_test.go` | secret-file permissions | negative (duplicate suppressed) | C/S: owner-only DB, rollback, archive, and journal modes checked; M/C/L: existing-file migration behavior reviewed; Parity: N/A; Perf: chmod at setup only; Mod: permissions spread across owners but tracked; Tests: old-mode concerns match `#4056`/`#5188`, no new root retained. |
| `pkg/configstore/history.go` | in-memory rollback ring | `A4-b1-F005`, `A4-b1-F007` | C/S: positional indexing is correct only while tombstones stay aligned with disk; M/C/L: fixed entry count does not bound retained bytes; Parity: rollback N semantics relevant; Perf: list clones pointer slice, startup AST footprint dominates; Mod: ring has no persisted identity; Tests: no byte-budget or shifted-tombstone restart test. |
| `pkg/configstore/load_compile_fail_test.go` | failed-load recovery | `A4-b1-F003`, `A4-b1-F006` | C/S: syntactic/compile failures surface and preserve recoverability; M/C/L: no added race; Parity: tolerant upgrade load relevant; Perf: startup compile only; Mod: Store/compiler boundary exercised; Tests: semantically malformed JSON `null` and wildcard-retired migration are absent. |
| `pkg/configstore/marker_test.go` | committed marker | `A4-b1-F002`, `A4-b1-F003` | C/S: valid 0/1 and legacy marker behavior covered; M/C/L: no concurrency concern; Parity: bootstrap classification relevant; Perf: constant-time parse; Mod: marker spans envelope, Store, and daemon contract; Tests: noncanonical values, AAD tampering, and `null` body absent. |
| `pkg/configstore/persist_failure_test.go` | degraded active persistence | `A4-b1-F001` | C/S: Option-B retry and health state work during a live process; M/C/L: singleton retry prevents duplicate retry workers; Parity: HA availability behavior covered; Perf: exponential backoff; Mod: retry centralized; Tests: process loss before retry after confirm-state deletion is not modeled. |
| `pkg/configstore/postrename_durability_5185_test.go` | post-rename fsync errors | `A4-b1-F001` | C/S: ambiguous durability errors propagate and retry; M/C/L: atomic replacement ownership checked; Parity: N/A; Perf: fsync is expected; Mod: typed fsatomic error contract used; Tests: no coupled confirm-record ordering assertion. |
| `pkg/configstore/rescue_delete_fsync_5197_test.go` | rescue deletion durability | negative (duplicate suppressed) | C/S: unlink and directory fsync behavior checked; M/C/L: no leak beyond tracked retry semantics; Parity: rescue lifecycle covered; Perf: one fsync; Mod: shared seams used; Tests: surviving candidates match tracked `#5197`. |
| `pkg/configstore/rescue_redaction_leak_4099_test.go` | rescue parse diagnostics | negative | C/S: parse errors log position without secret token; M/C/L: no secret buffer retained in logs; Parity: rescue workflow covered; Perf: boot-only; Mod: sanitization at logging boundary; Tests: malformed secret regression covered. |
| `pkg/configstore/rollback_corrupt_log_4690_test.go` | rollback corruption diagnostics | `A4-b1-F005` | C/S: corrupt slot becomes a positional tombstone without secret disclosure; M/C/L: read error continuation covered; Parity: rollback index stability intended; Perf: bounded count only; Mod: tombstone is memory-only; Tests: no subsequent-commit/restart assertion that stale valid bytes remain a tombstone. |
| `pkg/configstore/store_commit.go` | commit, confirm, rollback persistence | `A4-b1-F001`, `A4-b1-F005`, `A4-b1-F007`, `A4-b1-F008` | C/S: confirm recovery ordering and rollback slot identity fail; M/C/L: archive admission and history byte use are unbounded; Parity: commit-confirmed and rollback semantics reviewed; Perf: full config formatting plus unconstrained async backlog is material; Mod: several persistence state machines share Store lock without durable transaction record; Tests: retained gaps mapped to findings. |
| `pkg/configstore/store_persist.go` | boot load, retry, archive | `A4-b1-F001`, `A4-b1-F004`, `A4-b1-F008`, `A4-b1-F009` | C/S: boot recovery can erase intent before target durability; M/C/L: retry is singleton but archive workers are not; Parity: HA/reboot/archive behavior reviewed; Perf: retry backoff is bounded, archive work is not; Mod: archive naming/rotation lacks persistent generation; Tests: failure/crash, queue saturation, reset inventory, and clock reversal missing. |
| `pkg/configstore/system_action_journal_4108_test.go` | system-action audit records | negative | C/S: action metadata is journaled without full config secrets; M/C/L: compact records bound memory; Parity: operational audit behavior covered; Perf: control-plane append only; Mod: journal Entry contract reused; Tests: expected actions covered. |
| `pkg/configstore/test_seams.go` | persistence fault seams | negative | C/S: seams permit deterministic write/remove/fsync failures; M/C/L: package globals are test-reset and production defaults stable; Parity: N/A; Perf: indirection is off packet path; Mod: fault injection is localized; Tests: seams could express `A4-b1-F001`, but no such crash-order test exists. |

### Cryptography, envelope, and compatibility migration

| Path | Module/subsystem | Result | Invariant and review dimensions |
|---|---|---|---|
| `pkg/configstore/crypto.go` | AES-GCM config body | `A4-b1-F002`, `A4-b1-F003` | C/S: nonce/key derivation is sound, but outer boot metadata is excluded from AAD and JSON `null` falls through as plaintext; M/C/L: key/file reads checked, no unsafe memory; Parity: master-password at-rest behavior relevant; Perf: encryption is commit/load only; Mod: inner and outer envelopes have split integrity ownership; Tests: AAD and semantic body-shape cases missing. |
| `pkg/configstore/crypto_envelope_unknown_format_4888_test.go` | encrypted-envelope discriminator | `A4-b1-F003` | C/S: unknown nonempty format/AES fields fail closed; M/C/L: malformed base64 errors surface; Parity: upgrade safety covered; Perf: N/A; Mod: discriminator centralized; Tests: valid JSON scalars including `null` are not rejected. |
| `pkg/configstore/crypto_nonce_length_4793_test.go` | AES-GCM nonce validation | negative | C/S: decoded nonce length is checked before Open; M/C/L: panic path refuted; Parity: N/A; Perf: constant-time length gate; Mod: decrypt helper owns validation; Tests: short/long nonce cases covered. |
| `pkg/configstore/crypto_prf_sync_4578_test.go` | PRF validation and sync | negative | C/S: unsupported PRF cannot silently downgrade encryption; M/C/L: derivation errors return cleanly; Parity: HA encrypted-config convergence covered; Perf: KDF off hot path; Mod: PRF mapping has one implementation; Tests: local and sync paths covered. |
| `pkg/configstore/dataplane_retire.go` | retired-backend load rewrite | `A4-b1-F006` | C/S: direct `system` nodes are rewritten but wildcard group expansion bypasses migration; M/C/L: AST filtering owns new slice safely; Parity: retired backend compatibility affects vSRX-style upgrades but no forwarding parity gap is claimed; Perf: bounded boot/sync tree walk; Mod: rewrite duplicates only part of group semantics; Tests: wildcard top-level group missing. |
| `pkg/configstore/dataplane_retire_test.go` | retirement rewrite tests | `A4-b1-F006` | C/S: top-level, split, and literal group-system nodes covered; M/C/L: nil and multiple-node cases safe; Parity: retired eBPF/DPDK migration covered partially; Perf: N/A; Mod: tests target helper directly; Tests: `<*>` group node that materializes under `system` absent. |
| `pkg/configstore/db.go` | durable config database | `A4-b1-F002`, `A4-b1-F003`, `A4-b1-F004`, `A4-b1-F007` | C/S: durable replace is sound, but metadata/body validation and reset temp ownership are incomplete; M/C/L: startup `ReadFile` is unbounded and only DB-local temps are swept; Parity: boot persistence relevant; Perf: whole-file load and AST decode at startup; Mod: DB owns inner encryption but outer marker is separate; Tests: semantic scalar, AAD, and size cases absent. |
| `pkg/configstore/db_test.go` | DB round-trip tests | `A4-b1-F003`, `A4-b1-F007` | C/S: normal, absent, corrupt syntax, and round-trip states covered; M/C/L: ordinary file operations covered, unbounded file case absent; Parity: N/A; Perf: no large-file test; Mod: DB tested directly; Tests: writer never emits `null`, so a hand-crafted semantic corruption case is needed. |
| `pkg/configstore/envelope.go` | compatibility header | `A4-b1-F002` | C/S: version floor gates exist, but `committed` accepts every integer and remains unauthenticated; M/C/L: line length and token parsing checked; Parity: rolling-upgrade marker semantics relevant; Perf: one header line; Mod: compatibility and boot-security metadata share a permissive parser; Tests: canonical-value and integrity cases absent. |
| `pkg/configstore/envelope_test.go` | envelope tests | `A4-b1-F002` | C/S: writer/reader, unknown fields, and version floors covered; M/C/L: malformed token handling checked; Parity: compatibility behavior exercised; Perf: N/A; Mod: parser tested in isolation; Tests: `committed=-1/2` acceptance and encrypted-body/header tampering absent. |
| `pkg/configstore/journal_compat_test.go` | legacy journal compatibility | negative | C/S: legacy records are parsed without re-exposing full payload in new entries; M/C/L: bounded tail behavior checked; Parity: upgrade compatibility covered; Perf: bounded tail scan; Mod: compatibility remains journal-owned; Tests: no new storage root found. |
| `pkg/configstore/masterpw_apply_groups_5231_test.go` | wildcard group secret discovery | `A4-b1-F006` | C/S: proves top-level `<*>` group children become active under `system`; M/C/L: AST traversal is bounded; Parity: Junos apply-groups semantics covered; Perf: compile-time only; Mod: demonstrates why literal-node scans are incomplete; Tests: master-password is covered, retired dataplane rewrite is not. |
| `pkg/configstore/masterpw_split_system_4705_test.go` | split-system secret discovery | negative | C/S: all split `system` blocks influence encryption; M/C/L: traversal has no unsafe alias; Parity: hierarchical syntax covered; Perf: boot/commit only; Mod: PRF discovery helper centralized; Tests: split-node regression covered. |
| `pkg/configstore/plaintext_downgrade_warn_4579_test.go` | encryption downgrade warning | negative | C/S: plaintext carrying active master-password is observable; M/C/L: no secret value enters warning; Parity: migration behavior covered; Perf: load-only; Mod: DB read owns warning; Tests: expected warning/no-warning states covered, outer-header AAD remains `A4-b1-F002`. |

### Journal

| Path | Module/subsystem | Result | Invariant and review dimensions |
|---|---|---|---|
| `pkg/configstore/journal/journal.go` | durable audit journal | `A4-b1-F010` | C/S: migration refuses symlink chmod but append later follows the same link; M/C/L: mutex, torn-tail repair, rotation, and bounded tail checked; Parity: operational audit trail relevant; Perf: serialized fsync off packet path; Mod: secure-open invariant is not shared with migration; Tests: append-through-symlink missing. |
| `pkg/configstore/journal/journal_test.go` | journal tests | `A4-b1-F010` | C/S: append, rotation, torn tail, modes, and migration tested; M/C/L: concurrent append serialization covered; Parity: audit behavior covered; Perf: size rotation exercised; Mod: package-local black-box coverage; Tests: symlink test calls `Tail` only and never verifies `Append` rejection. |

### A5-b1: HA, VRRP, RA and conntrack synchronization (101 files)

Batch-list SHA-256: `2f3f51441bae55858226a6e278dc466c3bf3cd442a27d67714e46bfed5d63a6e`.

### Cluster HA and synchronization

Module-wide dimensions checked: election and transfer correctness, authentication and fail-open behavior, goroutine/timer/lock lifecycle, frame truncation and bounded allocation, vSRX role and monitor parity, control-path latency and queue backpressure, ownership boundaries, and negative-test completeness. The heartbeat and sync paths are control paths rather than packet hot paths; no new per-packet allocation or cache-line issue survived review. Existing tests cover many races, but the rows below call out the uncovered state transitions.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/cluster/cluster_test.go` | cluster manager integration tests | A5-b1-F005 | Explicit failover tests model local rollback but do not exercise the remote node after phase-one demotion. |
| `pkg/cluster/controllink_auth_status_4484_test.go` | control-link auth status | negative | Auth engagement and redaction are surfaced without exposing the key; no new correctness, leak, or parity issue survived. |
| `pkg/cluster/election.go` | RG election | negative | Weight-zero, readiness, duplicate-node, split-brain, and hold gates are bounded and serialized; monitor callers can still feed stale state as reported elsewhere. |
| `pkg/cluster/election_dup_nodeid_4549_test.go` | duplicate-node election tests | negative | Equal node IDs deterministically yield rather than electing dual primary. |
| `pkg/cluster/election_test.go` | election tests | negative | Peer loss, preempt, readiness, kernel hold, and non-preempt dual-active matrices cover the election core. |
| `pkg/cluster/events.go` | event history | negative | Ring bounds and per-category locking prevent unbounded growth and concurrent corruption. |
| `pkg/cluster/events_log.go` | event logging bridge | negative | Logging remains off packet paths and adds no mutable ownership. |
| `pkg/cluster/events_test.go` | event history tests | negative | Wrap, isolation, ordering, and concurrent access have direct coverage. |
| `pkg/cluster/failover.go` | manual and peer failover | A5-b1-F004, A5-b1-F005 | Batch all-or-none semantics and two-phase remote rollback fail under supersession or post-request failure. |
| `pkg/cluster/failover_races_5245_5246_test.go` | failover race regressions | A5-b1-F004 | Single-RG reset generation is covered, but the same per-member skip breaks the documented batch atomicity. |
| `pkg/cluster/garp.go` | direct GARP/NA | negative | Frame sizes, family selection, socket cleanup, abdication checks, and bounded follow-up bursts survived review. |
| `pkg/cluster/garp_abdicate_test.go` | GARP abdication tests | negative | Follow-up ARP/NA bursts stop after ownership loss. |
| `pkg/cluster/garp_burst_errors_test.go` | GARP error accounting tests | negative | Follow-up send failures remain observable and do not panic. |
| `pkg/cluster/garp_test.go` | GARP serialization tests | negative | ARP/NA byte order, checksum, source selection, and family rejection are pinned. |
| `pkg/cluster/group_state.go` | config-to-runtime RG state | A5-b1-F003 | Existing RG state is preserved, but removed/changed monitor contributions are not reconciled. |
| `pkg/cluster/heartbeat.go` | heartbeat wire/auth receiver | A5-b1-F001 | HMAC verification is sound, but session-ID rollback defeats anti-replay and feeds stale election state. |
| `pkg/cluster/heartbeat_auth_test.go` | heartbeat auth tests | A5-b1-F001 | Tests cover monotonic counters and one-way re-anchor, not return to a previously accepted session. |
| `pkg/cluster/heartbeat_family_4549_test.go` | heartbeat address-family tests | negative | IPv4/IPv6 socket-family selection and control-link startup are covered. |
| `pkg/cluster/heartbeat_guard_recheck_test.go` | timeout guard tests | negative | A fresh heartbeat during the guard window suppresses stale timeout action. |
| `pkg/cluster/heartbeat_liveness_test.go` | heartbeat liveness tests | negative | Monotonic ages and restart grace avoid wall-clock and stale-receiver errors. |
| `pkg/cluster/heartbeat_manager.go` | heartbeat manager integration | negative | Peer-map replacement, timeout fencing, and transfer grace are lock-serialized; accepted stale auth frames remain the upstream defect. |
| `pkg/cluster/heartbeat_neverseen_floor_test.go` | cold-boot liveness tests | negative | Never-seen peers cannot trigger premature promotion below the confirmation floor. |
| `pkg/cluster/heartbeat_rg_cap_4434_test.go` | heartbeat RG cap tests | negative | Oversized RG lists are bounded; the already tracked heartbeat-cap root was not re-reported. |
| `pkg/cluster/heartbeat_stop_previous_test.go` | heartbeat restart tests | negative | Starting a replacement heartbeat joins the previous sender/receiver set. |
| `pkg/cluster/heartbeat_test.go` | heartbeat codec tests | negative | Header, group, monitor, version-trailer, and maximum-frame truncation paths are covered. |
| `pkg/cluster/hooks.go` | manager hook registration | negative | Hook publication is lock-protected and callbacks are invoked outside inappropriate critical sections. |
| `pkg/cluster/kernel_selfrecover.go` | kernel upgrade hold | negative | Candidate hold prevents unsafe promotion and has explicit clear semantics. |
| `pkg/cluster/lease_sync_wire_test.go` | DHCP lease sync tests | A5-b1-F014 | Tests deliberately accept truncated full-set streams and do not assert malformed input preserves the prior authoritative set. |
| `pkg/cluster/manager.go` | cluster manager lifecycle/state | negative | Maps/channels are initialized consistently and stop state is bounded; no supported reuse contract justified a new finding. |
| `pkg/cluster/manager_start_deadlock_test.go` | manager start race test | negative | Start/monitor/stop lock ordering has a direct deadlock regression. |
| `pkg/cluster/manager_stop_test.go` | manager timer-stop tests | negative | Armed readiness timers cannot elect after manager stop. |
| `pkg/cluster/monitor.go` | interface/IP monitor engine | A5-b1-F002, A5-b1-F003 | Missing local interfaces fail open, and config replacement does not reconcile retained monitor state. |
| `pkg/cluster/monitor_test.go` | monitor tests | A5-b1-F002, A5-b1-F003 | Carrier-down and additive updates are covered; missing-link and monitor-removal/weight-change cases are absent. |
| `pkg/cluster/peer_state.go` | peer-state accessors | negative | Snapshots copy mutable slices/maps and avoid exposing manager-owned state. |
| `pkg/cluster/readiness.go` | takeover readiness | negative | Timer cancellation and staleness guards prevent removed/not-ready groups from promoting. |
| `pkg/cluster/reth.go` | RETH MAC/state hooks | negative | RG filtering and deterministic MAC derivation avoid cross-RG action. |
| `pkg/cluster/reth_test.go` | RETH tests | negative | MAC derivation, mapping status, and state-change filtering are covered. |
| `pkg/cluster/runtime.go` | runtime domain adapter | negative | Session and telemetry interfaces remain narrow; no legacy forwarding dependency was introduced. |
| `pkg/cluster/status.go` | HA status rendering | A5-b1-F015, A5-b1-F016 | IP-monitor configuration and inbound bulk counts are fabricated rather than derived from authoritative state. |
| `pkg/cluster/sync.go` | session-sync state/reconciliation | A5-b1-F006, A5-b1-F014 | Empty bulk handling is non-authoritative and malformed lease decoding replaces held state. |
| `pkg/cluster/sync_accept_test.go` | sync accept tests | negative | Slow handshakes no longer serialize accepts; the related resource-pressure root is already tracked as `#4370` and was suppressed. |
| `pkg/cluster/sync_auth.go` | sync handshake/frame auth | negative | HMAC, nonce binding, frame sequence, size cap, and downgrade gates survived review. |
| `pkg/cluster/sync_auth_test.go` | sync auth tests | negative | Key match/mismatch, legacy dual-accept, downgrade, replay, and nonce binding are covered. |
| `pkg/cluster/sync_bulk.go` | outbound bulk protocol | A5-b1-F006 | Marker-only override writes bypass the ordered session queue and cannot identify an authoritative empty set. |
| `pkg/cluster/sync_config_gen_test.go` | config generation tests | negative | Ordered apply, stale rejection, retry after apply failure, and reboot reset are covered. |
| `pkg/cluster/sync_conn.go` | sync connection/send/receive loops | A5-b1-F005, A5-b1-F006, A5-b1-F007, A5-b1-F013, A5-b1-F014 | Reconnect priming, queue ordering, failover phases, and malformed payload admission contain retained defects. |
| `pkg/cluster/sync_failover.go` | failover wire protocol | A5-b1-F005 | Request and commit have acknowledgements and IDs, but there is no abort message/state to undo an applied request. |
| `pkg/cluster/sync_gen_guard_test.go` | session generation tests | negative | Stale install/delete and overflow tests are extensive; `#2170/#2198` overflow and atomicity roots were duplicate-suppressed. |
| `pkg/cluster/sync_protocol.go` | sync payload codecs | A5-b1-F013, A5-b1-F014 | Session core-field groups and DHCP authoritative sets accept malformed truncation instead of returning an error. |
| `pkg/cluster/sync_state.go` | sync statistics state | negative | Atomic counters and snapshot reads are race-safe; the formatter misuses one outbound counter separately. |
| `pkg/cluster/sync_test.go` | sync integration tests | A5-b1-F006, A5-b1-F007, A5-b1-F013 | Tests lock in empty-bulk/reconnect behavior and only reject payloads shorter than the key, leaving the reported cases uncovered. |

### Conntrack GC

Module-wide dimensions checked: v4/v6 expiration parity, primary/secondary ownership, partial batch deletion, callback ordering, scratch-buffer reuse, locking, adaptive latency, session-limit work, userspace skip behavior, and legacy dependency boundaries. The production userspace path can skip this GC, but the runtime-domain API and legacy-compatible path remain live code and tests; the retained defect is specifically in that active sweep implementation.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/conntrack/gc.go` | adaptive conntrack GC | A5-b1-F008 | Empty-table telemetry fast path can prevent the periodic IPv6 discovery counter from ever advancing. |
| `pkg/conntrack/gc_test.go` | conntrack GC tests | A5-b1-F008 | Expiry, partial deletes, races, and adaptive delays are covered; first IPv6 arrival after an empty snapshot is not. |
| `pkg/conntrack/legacy_dataplane_canary_test.go` | modularity canary | negative | AST/type walkers reject production dependencies on the retired legacy dataplane without false matching unrelated types. |

### Router advertisements

Module-wide dimensions checked: NDP socket ownership, shutdown/goodbye ordering, timer reclamation, concurrent apply/withdraw serialization, RS validation, per-interface epochs, config equality, packet serialization, allocation behavior, vSRX RA fields, and recovery tests. No non-duplicate RA finding survived: the initial-open dead-sender root is already tracked as `#2865`; the current code rebuilds it on a later `Apply`, and the broader residual was therefore suppressed rather than rephrased.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/ra/filter.go` | ICMPv6 filter construction | negative | Filter permits only Router Solicitations and performs fixed-size bit operations. |
| `pkg/ra/per_iface_epoch_4961_test.go` | per-interface epoch tests | negative | A withdraw on one interface cannot cancel another interface's restart. |
| `pkg/ra/ra.go` | RA manager/ownership | negative | Tombstone claim, stop/join, goodbye claim, and replacement decisions are serialized without conflicting mutable ownership; known dead-open root suppressed. |
| `pkg/ra/ra_test.go` | RA config/packet tests | negative | Prefix lifetimes, flags, NAT64, timers, config equality, and marshal round trips are covered. |
| `pkg/ra/rs_receive_validation_5095_test.go` | RS validation tests | negative | Missing/wrong hop limit and off-link sources fail closed. |
| `pkg/ra/sender.go` | RA sender loop | negative | Single owner controls the socket, writes, timer cleanup, and shutdown; periodic work is bounded and off packet paths. |
| `pkg/ra/sender_interval_4525_test.go` | interval tests | negative | Minimum/maximum advertisement interval normalization is pinned. |
| `pkg/ra/sender_linklocal_test.go` | link-local tests | negative | Link-local selection and ensure behavior avoid invalid family/source choices. |
| `pkg/ra/sender_marshal_3895_test.go` | marshal pruning tests | negative | Oversized options are pruned without losing mandatory RA validity. |
| `pkg/ra/sender_marshal_4119_test.go` | malformed option tests | negative | Option marshal failures do not emit partial malformed packets. |
| `pkg/ra/sender_marshal_4307_test.go` | source-LLA tests | negative | Source link-layer option sizing and absence behavior are covered. |
| `pkg/ra/serialize_test.go` | manager/sender concurrency tests | negative | Single-connection, goodbye-last, restart, timeout, claim, slow-bind, and dead-sender rebuild invariants have extensive race tests. |
| `pkg/ra/timer_leak_4830_test.go` | timer lifecycle tests | negative | Wait timers are stopped on the fast arm and do not accumulate until timeout. |

### VRRP

Module-wide dimensions checked: VRRPv3 checksum and receive validation, interface binding, AF_PACKET/raw fallback, IPv6 source and hop limit, VIP ownership, role transitions, sync hold, preempt/hold timers, manager reuse, config reconciliation, GARP/NA behavior, lock/race discipline, per-advert latency, vSRX parity, and negative-test coverage. Receive parsing is bounded and no packet-path allocation regression survived; retained issues are control-plane readiness, transactionality, and teardown defects.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/vrrp/addrwatch.go` | address/link watcher | negative | Ifindex/name cache and address re-resolution are generation-safe and avoid stale source races. |
| `pkg/vrrp/addrwatch_test.go` | watcher tests | negative | Changed addresses, recreated links, late interfaces, and unrelated updates are covered. |
| `pkg/vrrp/afpacket_cloexec_test.go` | AF_PACKET FD tests | negative | Receiver sockets request `SOCK_CLOEXEC` and real descriptors retain it. |
| `pkg/vrrp/afpacket_membership_test.go` | multicast membership tests | negative | ALLMULTI and destination MAC constants are pinned; tests do not prove setup-error propagation, which is folded into readiness review. |
| `pkg/vrrp/bindtodevice_test.go` | device-binding tests | negative | VLAN and plain-interface bind decisions match both IPv4/IPv6 call sites. |
| `pkg/vrrp/instance.go` | VRRP state machine/socket/VIP owner | A5-b1-F010, A5-b1-F011, A5-b1-F012 | IPv6 setup, VIP role commits, and graceful stop ordering can report success without required side effects. |
| `pkg/vrrp/instance_arp_probe_test.go` | ARP probe tests | negative | Probe sender uses each VIP and skips gateway self-probes. |
| `pkg/vrrp/instance_garp_abdicate_test.go` | GARP abdication test | negative | A delayed burst rechecks master ownership before sending. |
| `pkg/vrrp/instance_garp_force_test.go` | forced GARP tests | negative | Epoch dedup, dampening bypass, reconciliation, and suppression are covered. |
| `pkg/vrrp/instance_garp_probe_target_test.go` | probe target tests | negative | Network+1 target computation handles long and host prefixes. |
| `pkg/vrrp/instance_garp_test.go` | GARP dampening test | negative | Routine bursts are bounded by the dampener. |
| `pkg/vrrp/instance_ifindex_filter_test.go` | raw fallback ifindex tests | negative | Cross-VLAN frames are rejected when cmsg data exists; the zero-ifindex fail-open root is already tracked as `#2886`. |
| `pkg/vrrp/instance_localip_race_test.go` | local-address race tests | negative | Concurrent lazy IPv4/IPv6 resolution is race-clean. |
| `pkg/vrrp/instance_master_interval_test.go` | learned interval tests | negative | Peer interval conversion, floors, and priority-zero exclusion are covered. |
| `pkg/vrrp/instance_owner_preempt_test.go` | address-owner tests | negative | Priority 255 preempts irrespective of configured preempt, matching RFC/vSRX behavior. |
| `pkg/vrrp/instance_preempt_gate_test.go` | preempt gate tests | negative | Live-master priority, stale-master, force, no-preempt, and tracking gates are covered. |
| `pkg/vrrp/instance_preempt_hold_revalidate_test.go` | hold revalidation tests | negative | Config and priority changes invalidate an armed hold on the run-loop goroutine. |
| `pkg/vrrp/instance_preempt_hold_watchdog_test.go` | hold watchdog tests | negative | A held master that goes silent is taken over promptly. |
| `pkg/vrrp/instance_preempt_holdtime_test.go` | hold-time tests | negative | Live lower masters defer, dead masters and priority-zero resignations bypass the hold. |
| `pkg/vrrp/instance_rxdrop_race_test.go` | RX-drop telemetry tests | negative | Atomic counters and warning dampening are race-safe and bounded. |
| `pkg/vrrp/instance_v6_hoplimit_test.go` | IPv6 GTSM tests | negative | Raw IPv6 fallback rejects hop limit other than 255. |
| `pkg/vrrp/instance_v6_pktinfo_test.go` | IPv6 source tests | negative | Pktinfo source/ifindex equals the checksum pseudo-header source. |
| `pkg/vrrp/instance_vipset_canon_test.go` | VIP canonicalization tests | negative | Canonical VIP exclusion prevents selecting a VIP as the local advert source. |
| `pkg/vrrp/manager.go` | VRRP manager/reconcile/socket setup | A5-b1-F009, A5-b1-F010 | Config diff omits live fields and suppressed socket failures can still satisfy readiness. |
| `pkg/vrrp/manager_garp_unsuppress_test.go` | GARP suppression tests | negative | Only the true-to-false master edge forces a burst. |
| `pkg/vrrp/manager_reuse_test.go` | manager reuse tests | negative | Channels, contexts, and watcher generations are recreated; the broader `#2625` reuse root was duplicate-suppressed. |
| `pkg/vrrp/packet.go` | VRRP packet codec | negative | Version/type/count, v4/v6 pseudo-header checksums, and length bounds survived review. |
| `pkg/vrrp/packet_checksum_test.go` | checksum tests | negative | RFC vector, pseudo-header, legacy compatibility, corruption, and missing-address cases are covered. |
| `pkg/vrrp/track.go` | tracked-interface priority | negative | Link state, polling fallback, owner exemption, and priority clamp are lock-safe and off packet paths. |
| `pkg/vrrp/track_test.go` | tracking tests | negative | Rename-away, subscription failure, polling, updates, and watcher singleton behavior are covered. |
| `pkg/vrrp/update_instances_test.go` | instance reconcile tests | A5-b1-F009, A5-b1-F010 | Build-before-teardown and ifindex drift are covered; interval/GARP-only changes and IPv6 sub-socket failure are not. |
| `pkg/vrrp/vrid_guard_4573_test.go` | VRID range tests | negative | Out-of-range IDs are rejected and 1/255 boundaries build. |
| `pkg/vrrp/vrrp.go` | config-to-instance compiler | A5-b1-F009 | Advert interval and GARP count reach desired instances but are lost by the manager's change detector. |
| `pkg/vrrp/vrrp_test.go` | VRRP integration/unit tests | A5-b1-F009, A5-b1-F012 | Collection, packet, sync hold, election, raw parsing, and GARP tests omit live-field reconcile and stop-wire resignation. |

### A6-b1: Go dataplane manager and control publication (125 files)

Batch-list SHA-256: `7a70aa5d4fd5377949b2aa139597398b0769d454651c7ba3b523fadcab832e80`.

### Core compiler, apply, ABI, and loader

Dimension sweep: correctness/security/fail-open review covered compile failure propagation, immutable publication inputs, and ABI gates; memory/concurrency/truncation/leak review covered Go ownership, integer widths, map pin lifetimes, and loader cleanup; vSRX completeness covered AppID, filters, interfaces, NAT/NPTv6, and default behavior; performance covered compile-time expansion and startup-only work rather than packet-path work; modularity covered single-source constants and compiler/DataPlane boundaries; tests were checked for positive, negative, reorder, collision, and ABI-drift coverage. Negative result: aside from F002 and F004, no surviving contract violation was found in this module.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/appid_catalog_parity_test.go` | AppID compiler parity | negative | Built-in catalog IDs, tuple fallback, and userspace publication remain aligned. |
| `pkg/dataplane/appid_catalog_port_zero_5194_test.go` | AppID port handling | negative | Port zero is not promoted into an unsafe wildcard application match. |
| `pkg/dataplane/apply.go` | Config apply | negative | Compile/apply errors stop publication and stale map cleanup is sequenced after writes. |
| `pkg/dataplane/apply_test.go` | Config apply tests | negative | Apply ordering, defaults, and failure propagation have regression coverage. |
| `pkg/dataplane/bpf_session_value.go` | Conntrack ABI conversion | negative | Sync-only fields are excluded and fixed-width BPF values are copied without truncation. |
| `pkg/dataplane/bpf_session_value_test.go` | Conntrack ABI tests | negative | V4/V6 conversion and exact on-map sizes are pinned by tests. |
| `pkg/dataplane/compiler.go` | Compiler orchestration | negative | Zone/policy/filter/NAT compilation propagates errors instead of publishing partial state. |
| `pkg/dataplane/compiler_filter.go` | Firewall filter compiler | negative | Unresolved/invalid match dimensions do not silently broaden a term. |
| `pkg/dataplane/compiler_filter_expansion_test.go` | Filter expansion tests | negative | Multi-value expansion remains bounded and preserves match conjunctions. |
| `pkg/dataplane/compiler_filter_protocol_test.go` | Filter protocol tests | negative | IPv4/IPv6 protocol selectors and incompatible families are represented consistently. |
| `pkg/dataplane/compiler_iface.go` | Interface compiler | negative | Protected interfaces, logical indices, and per-interface publication use checked identities. |
| `pkg/dataplane/compiler_nat.go` | NAT compiler/counter IDs | A6-b1-F004 | Per-rule cumulative counter identity must remain stable even when two rule keys hash alike. |
| `pkg/dataplane/compiler_nat_counter_collision_test.go` | NAT counter tests | A6-b1-F004 | Type namespacing is tested, but a genuine same-type FNV collision is not. |
| `pkg/dataplane/compiler_nat_counter_stability_test.go` | NAT counter stability tests | A6-b1-F004 | Reorder/removal tests use noncolliding keys and miss encounter-order collision fallback. |
| `pkg/dataplane/compiler_test.go` | Compiler integration tests | negative | Compiler defaults, IDs, and map writes are deterministic for covered inputs. |
| `pkg/dataplane/constants.go` | Go/BPF ABI constants | negative | Map capacities, flags, sentinels, and counter ordinals retain fixed widths. |
| `pkg/dataplane/constants_test.go` | ABI constant tests | negative | Key/value sizes and contract constants are checked against expected values. |
| `pkg/dataplane/cpumask.go` | CPU mask parsing | negative | Sparse masks, range bounds, and malformed input return errors without oversized allocation. |
| `pkg/dataplane/cpumask_test.go` | CPU mask tests | negative | Empty, malformed, sparse, and range mask cases are covered. |
| `pkg/dataplane/current_sessions_test.go` | Session accounting tests | negative | Current-session totals do not underflow or conflate forward/reverse entries. |
| `pkg/dataplane/dataplane.go` | DataPlane contract | negative | Control-plane methods expose explicit errors and typed V4/V6/map operations. |
| `pkg/dataplane/default_test.go` | Default dataplane tests | negative | Default policy and zero-value behavior remain fail-closed. |
| `pkg/dataplane/legacy_bpf_manifest_canary_test.go` | Retirement canary | negative | Retired forwarding objects cannot re-enter the sole userspace runtime manifest. |
| `pkg/dataplane/loader.go` | Manager/loader lifecycle | negative | Map/program ownership, mutex scope, and close paths do not expose a surviving leak or race. |
| `pkg/dataplane/loader_userspace_shim.go` | Userspace shim ABI/load | A6-b1-F002 | Every retained PinByName map must be ABI-checked before the old daemon is stopped. |

### Maps, sessions, runtime types, and compatibility state

Dimension sweep: correctness/security/fail-open review covered map-not-found behavior, clear semantics, stale cleanup, and session/NAT companion handling; memory/concurrency/truncation/leak review covered per-CPU aggregation, bounded session chunks, lock scopes, pointer snapshots, and map iteration; vSRX completeness covered flow/session/NAT/proxy-ARP/screen counters and NPTv6; performance covered batch operations, `Gosched` yielding, bounded snapshots, and O(1) counter reads; modularity covered map-family separation and runtime DTO boundaries; tests were checked for empty/full/error/concurrent cases. Negative result: F003 survives; session-delete-error and live-pointer candidates were refuted as described in Verification.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/maps_counters.go` | Global/interface/zone counters | A6-b1-F003 | Clear-all must clear every component that `ReadGlobalCounter` sums. |
| `pkg/dataplane/maps_fabric.go` | Fabric generation map | negative | Generation reads/writes use fixed keys and return lookup/update failures. |
| `pkg/dataplane/maps_filter.go` | Filter maps/counters | negative | Missing configs and per-CPU counter reads are distinguished from valid zero. |
| `pkg/dataplane/maps_flow.go` | Flow configuration maps | negative | Flow limits/timeouts are written at fixed indices without width drift. |
| `pkg/dataplane/maps_helpers.go` | Generic map helpers | negative | Batch/iteration helpers preserve error and count semantics for callers. |
| `pkg/dataplane/maps_mirror.go` | Mirror maps | negative | Mirror writes/deletes use typed keys and do not alias V4/V6 state. |
| `pkg/dataplane/maps_nat.go` | NAT maps/counters | negative | Byte order, pool/rule bounds, sparse userspace offsets, and clear behavior are coherent. |
| `pkg/dataplane/maps_policy.go` | Policy maps/counters | negative | Policy rule publication and per-CPU aggregation retain checked indices. |
| `pkg/dataplane/maps_screen.go` | Screen maps | negative | Screen configuration and sparse counters use bounded/stable zone identities. |
| `pkg/dataplane/maps_session.go` | Session maps/clear | negative | V4/V6 clears are chunk-bounded and helper callbacks receive every enumerated key. |
| `pkg/dataplane/maps_session_clear_test.go` | Session clear tests | negative | Empty, small, batched, bounded-memory, and callback behavior are exercised. |
| `pkg/dataplane/maps_stale.go` | Stale map cleanup | negative | Populate-before-clear cleanup targets only keys absent from the new generation. |
| `pkg/dataplane/maps_stats.go` | Map statistics | negative | Stats iteration closes no borrowed handles and reports map metadata without mutation. |
| `pkg/dataplane/maps_stats_test.go` | Map statistics tests | negative | Loaded/missing map stats and stable naming are covered. |
| `pkg/dataplane/nptv6_test.go` | NPTv6 publication tests | negative | Prefix lengths, bidirectional translation fields, and checksum-neutral data are preserved. |
| `pkg/dataplane/pci_function_suffix_4795_test.go` | Interface identity tests | negative | PCI function suffixes remain distinct rather than collapsing queue/interface ownership. |
| `pkg/dataplane/persistent_nat.go` | Persistent NAT compatibility table | negative | `All` returns copies under lock; expired binding and GC behavior are bounded. |
| `pkg/dataplane/persistent_nat_test.go` | Persistent NAT tests | negative | Snapshot-copy/race, timeout, permit mode, IPv6, and pool lookup behavior are covered. |
| `pkg/dataplane/protected_iface_test.go` | Protected-interface tests | negative | Management/protected interfaces cannot be admitted into transit publication. |
| `pkg/dataplane/proxyarp.go` | Proxy ARP reconciliation | negative | Address ownership and stale removal remain tied to desired NAT/interface state. |
| `pkg/dataplane/proxyarp_orphan_4955_test.go` | Proxy ARP orphan test | negative | Orphaned entries are removed without deleting still-owned neighbors. |
| `pkg/dataplane/proxyarp_test.go` | Proxy ARP tests | negative | Add/delete/idempotence and address-family filtering are covered. |
| `pkg/dataplane/retirement_boundary_canary_test.go` | Retirement/shared-map canary | negative | The retained shared-map set is explicit and legacy forwarding dependencies stay absent. |
| `pkg/dataplane/runtime/import_canary_test.go` | Runtime import boundary | negative | Runtime DTOs do not pull retired dataplane implementation dependencies back in. |
| `pkg/dataplane/runtime/session_delta.go` | Session delta DTO | negative | Session events preserve fixed-width tuple, policy, owner-RG, and generation fields. |
| `pkg/dataplane/screen_reason_counters_3343_test.go` | Screen counter contract | negative | Reason names and global counter ordinals remain a single source of truth. |
| `pkg/dataplane/session_store.go` | Session store adapter | negative | Companion deletes, persistent NAT preservation, and clear routing preserve V4/V6 ownership. |
| `pkg/dataplane/session_store_test.go` | Session store tests | negative | Companion deletion, clear delegation, generation, and persistent NAT cases are covered. |
| `pkg/dataplane/types.go` | Map/wire types | negative | Struct layouts, address/port byte order, flags, and counter widths are explicit. |

### Userspace snapshot builder, boot, control, CoS, and policy publication

Dimension sweep: correctness/security/fail-open review covered unresolved objects, default deny, helper readiness, request validation, and snapshot rejection; memory/concurrency/truncation/leak review covered JSON size caps, socket deadlines, copied snapshots, and controller ownership; vSRX completeness covered address books, applications, inactivity timeout, NAT views, CoS, default policy, and logs; performance covered control-socket contention, bounded requests, and cold-path sampling; modularity covered builder/capability/controller separation; tests include negative representability and fail-closed cases. Negative result: no new finding survived; signed control-ID wrapping is a strict duplicate of the prior `pkg/dataplane/userspace/control.go` finding in the dedup corpus.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/address_book_collision_2514_test.go` | Address-book snapshot | negative | Same-name/global-zone address books cannot silently overwrite one another. |
| `pkg/dataplane/userspace/address_book_test.go` | Address-book snapshot tests | negative | Prefix/address-set resolution and unresolved members fail closed. |
| `pkg/dataplane/userspace/addressbook_slash_name_4340_test.go` | Address-book naming | negative | Slash-bearing names remain identities rather than being reparsed as prefixes. |
| `pkg/dataplane/userspace/app_catalog_test.go` | App catalog snapshot | negative | Built-in and configured application IDs/tuples publish consistently. |
| `pkg/dataplane/userspace/app_inactivity_timeout_3227_test.go` | App timeout snapshot | negative | Application inactivity timeout reaches the helper snapshot. |
| `pkg/dataplane/userspace/app_inactivity_timeout_precedence_3298_test.go` | App timeout precedence | negative | Rule/application/default timeout precedence matches policy semantics. |
| `pkg/dataplane/userspace/app_set_reject_3727_test.go` | App-set integrity | negative | Unrepresentable app sets reject the snapshot instead of widening policy. |
| `pkg/dataplane/userspace/applied_nat_view.go` | Applied NAT status view | negative | Status is derived from the accepted snapshot rather than uncommitted config. |
| `pkg/dataplane/userspace/applied_nat_view_test.go` | Applied NAT view tests | negative | Source/destination/static NAT rows retain accepted-generation identities. |
| `pkg/dataplane/userspace/binding_ready_gate_test.go` | Binding readiness | negative | Forwarding does not arm before required binding/queue state is ready. |
| `pkg/dataplane/userspace/boot_probe.go` | Boot capability probe | negative | Probe failures and unsupported capabilities prevent unsafe forwarding enablement. |
| `pkg/dataplane/userspace/boot_probe_test.go` | Boot probe tests | negative | Missing helper, malformed output, timeout, and capability paths are covered. |
| `pkg/dataplane/userspace/builder.go` | Snapshot builder | negative | Publication is immutable, generation-stamped, and rejects unrepresentable content. |
| `pkg/dataplane/userspace/capabilities.go` | Capability derivation | negative | Reported support reflects complete config features rather than optimistic defaults. |
| `pkg/dataplane/userspace/clear_bounded_5304_test.go` | Userspace clear integration | negative | Authoritative helper deletes are driven per bounded mirror chunk. |
| `pkg/dataplane/userspace/cold_path_sample_mask_test.go` | Cold-path sampling | negative | Sampling masks are bounded and power-of-two semantics are preserved. |
| `pkg/dataplane/userspace/cold_path_status_test.go` | Cold-path status | negative | Status reflects helper counters and does not fabricate sampled coverage. |
| `pkg/dataplane/userspace/configstore_helper_test.go` | Configstore/helper boundary | negative | Helper snapshot validation is exercised through the configured mode boundary. |
| `pkg/dataplane/userspace/control.go` | Helper control socket | negative (duplicate suppressed) | Request size/deadline handling is bounded; negative numeric IDs still wrap, already reported. |
| `pkg/dataplane/userspace/control_request_cap_2744_test.go` | Control request cap | negative | Oversized requests are rejected before unbounded allocation/write. |
| `pkg/dataplane/userspace/control_socket_deadline_4036_test.go` | Control deadlines | negative | Read/write deadlines bound a stalled helper socket. |
| `pkg/dataplane/userspace/control_test.go` | Control protocol tests | negative | JSON framing, errors, request/response, and malformed replies are covered. |
| `pkg/dataplane/userspace/controllers.go` | Controller lifecycle | negative | Start/stop ownership and cancellation avoid duplicate loops and leaked goroutines. |
| `pkg/dataplane/userspace/cos.go` | CoS snapshot | negative | Scheduler/queue/shaper values are checked and published at interface scope. |
| `pkg/dataplane/userspace/cos_iface_level_4021_test.go` | CoS interface scope | negative | Interface-level classifiers and schedulers are not dropped from the snapshot. |
| `pkg/dataplane/userspace/default_policy_3065_test.go` | Default policy | negative | Missing explicit policy publishes the configured default action without fail-open. |
| `pkg/dataplane/userspace/default_policy_counter_3363_test.go` | Default counter | negative | Implicit default-policy hits retain a stable sentinel identity. |
| `pkg/dataplane/userspace/default_policy_log_3534_test.go` | Default policy logging | negative | Default deny/permit log flags reach the helper snapshot. |

### Event stream, fabric, fairness, filters, and flow publication

Dimension sweep: correctness/security/fail-open review covered ACK/replay gates, HA convergence, fabric state, filter exceptions, and wire coercion; memory/concurrency/truncation/leak review covered payload caps, callback queues, write serialization, snapshots, and integer narrowing; vSRX completeness covered default policy, FBF, feeds, flexible match, next-term, prefix lists, IPv6 protocol, CoS fairness, and flow widths; performance covered no packet-path work in Go, bounded callback/control queues, and precomputed snapshots; modularity covered event/session versus telemetry semantics and renderer separation; tests include races and many negative policy cases but omit malformed correctness-critical session frames. Negative result: only F001 survives in this module.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/eventstream.go` | Session/telemetry event stream | A6-b1-F001 | A cumulative ACK must never advance beyond an unapplied correctness-critical session delta. |
| `pkg/dataplane/userspace/eventstream_test.go` | Event stream tests | A6-b1-F001 | Gap and malformed-telemetry tests omit malformed session followed by valid telemetry. |
| `pkg/dataplane/userspace/eventstream_writeframe_race_4835_test.go` | Event write race test | negative | Concurrent control writes remain frame-atomic under the write mutex. |
| `pkg/dataplane/userspace/fabric.go` | Fabric snapshot | negative | Fabric generation/up state is published consistently and errors do not arm transit. |
| `pkg/dataplane/userspace/fabric_up_4082_test.go` | Fabric-up tests | negative | Fabric readiness reaches the helper and gates expected behavior. |
| `pkg/dataplane/userspace/fairness.go` | Fairness snapshot | negative | Queue weights/rates are normalized outside the packet path with bounded values. |
| `pkg/dataplane/userspace/fairness_test.go` | Fairness tests | negative | Weight, disabled, malformed, and normalization cases are covered. |
| `pkg/dataplane/userspace/fairness_throughput.go` | Fairness throughput model | negative | Throughput estimates avoid overflow/divide-by-zero and remain status-only. |
| `pkg/dataplane/userspace/fairness_throughput_test.go` | Throughput tests | negative | Counter delta/reset and elapsed-time edge cases are covered. |
| `pkg/dataplane/userspace/fbf_snapshot_test.go` | Filter-based forwarding | negative | FBF routing-instance actions survive snapshot publication. |
| `pkg/dataplane/userspace/feed_enforcement_test.go` | Dynamic feed policy | negative | Feed-backed prefixes reach runtime enforcement rather than status only. |
| `pkg/dataplane/userspace/filtercounters.go` | Filter counters | negative | Helper counters are keyed/stored/read without dense-index aliasing. |
| `pkg/dataplane/userspace/filters.go` | Firewall filter snapshot | negative | Unresolved except clauses and unsupported matches reject or fail closed. |
| `pkg/dataplane/userspace/filters_address_except_3359_test.go` | Address except | negative | Address exceptions retain exclusion semantics. |
| `pkg/dataplane/userspace/filters_address_matchany_except_4338_test.go` | Match-any except | negative | Wildcard plus exclusion does not collapse to an unconditional match. |
| `pkg/dataplane/userspace/filters_flex_match_3077_test.go` | Flexible match | negative | Offset/length/value masks are represented with bounds and family checks. |
| `pkg/dataplane/userspace/filters_multivalue_2545_test.go` | Multi-value filters | negative | Lists preserve OR-within-field and AND-across-field semantics. |
| `pkg/dataplane/userspace/filters_next_term_2544_test.go` | Next-term action | negative | Nonterminal action continues evaluation rather than becoming permit. |
| `pkg/dataplane/userspace/filters_per_packet_match_2362_test.go` | Per-packet filter fields | negative | TCP flags, fragment, ICMP, and other cache-sensitive fields reach runtime matching. |
| `pkg/dataplane/userspace/filters_port_except_2622_test.go` | Port except | negative | Port exclusions do not broaden inverted or empty ranges. |
| `pkg/dataplane/userspace/filters_prefix_list_2506_test.go` | Prefix-list filters | negative | Prefix-list resolution retains family and unresolved-reference behavior. |
| `pkg/dataplane/userspace/filters_protocol_ipv6_3393_test.go` | IPv6 protocol filters | negative | `protocol`/`next-header` semantics are not silently dropped for IPv6. |
| `pkg/dataplane/userspace/filters_snapshot_integrity_3406_test.go` | Snapshot integrity | negative | Unrepresentable filter content rejects the whole snapshot. |
| `pkg/dataplane/userspace/filters_unresolved_except_5097_test.go` | Unresolved exclusions | negative | Missing exclusion references fail closed rather than disappearing. |
| `pkg/dataplane/userspace/firewall_snapshot_render.go` | Firewall snapshot renderer | negative | Rendered terms preserve accepted ordering, actions, and optional constraints. |
| `pkg/dataplane/userspace/flow.go` | Flow config publication | negative | Timeout/session-limit/logging fields use checked widths and defaults. |
| `pkg/dataplane/userspace/flow_numwidth_agreement_test.go` | Flow width contract | negative | Go numeric widths agree with the helper wire schema. |
| `pkg/dataplane/userspace/flow_wire_coerce_test.go` | Flow wire coercion | negative | Overflow/negative values are rejected or clamped according to the explicit contract. |

### Operator formatting

Dimension sweep: correctness/security/fail-open review covered truthful status labels, absent-versus-zero values, and section selection; memory/concurrency/truncation/leak review found only bounded local builders and no shared mutation; vSRX completeness covered buffer, CoS, and system/status rows; performance is status-path-only with linear formatting and no packet-path coupling; modularity separates models, section renderers, and show dispatch; golden and focused tests cover long values, optional sections, arithmetic edges, and stable output. Negative result: no surviving finding or material test gap was found.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/format/buffers.go` | Buffer status rendering | negative | Buffer/drop counters are labeled and aggregated without fabricating availability. |
| `pkg/dataplane/userspace/format/buffers_golden_test.go` | Buffer golden output | negative | Stable operator-visible rows and ordering are pinned. |
| `pkg/dataplane/userspace/format/buffers_model.go` | Buffer status model | negative | Aggregation fields retain distinct drop/backpressure causes. |
| `pkg/dataplane/userspace/format/buffers_test.go` | Buffer renderer tests | negative | Detail/summary and empty/nonzero cases are covered. |
| `pkg/dataplane/userspace/format/cos.go` | CoS rendering | negative | Queue/scheduler units and unavailable values are represented truthfully. |
| `pkg/dataplane/userspace/format/cos_golden_test.go` | CoS golden output | negative | Stable Junos-style CoS sections are pinned. |
| `pkg/dataplane/userspace/format/cos_sections.go` | CoS sections | negative | Interface, queue, and scheduler sections use the correct source fields. |
| `pkg/dataplane/userspace/format/cos_show.go` | CoS show dispatch | negative | Selector handling returns the intended section without hidden broadening. |
| `pkg/dataplane/userspace/format/cos_show_test.go` | CoS dispatch tests | negative | Supported/unsupported selectors and empty status are covered. |
| `pkg/dataplane/userspace/format/cos_test.go` | CoS renderer tests | negative | Rates, percentages, queue rows, and optional data are covered. |
| `pkg/dataplane/userspace/format/math.go` | Formatting arithmetic | negative | Rate/delta helpers avoid divide-by-zero and unsigned underflow. |
| `pkg/dataplane/userspace/format/status.go` | Userspace status rendering | negative | Health/capability/counter fields distinguish unavailable, disabled, and zero. |
| `pkg/dataplane/userspace/format/status_golden_test.go` | Status golden output | negative | Stable status wording and section ordering are pinned. |
| `pkg/dataplane/userspace/format/status_sections.go` | Status sections | negative | Binding, event, NAT, filter, and security counters map to the right labels. |
| `pkg/dataplane/userspace/format/status_test.go` | Status renderer tests | negative | Feature rows, counters, empty values, and detailed sections are covered. |

### A6-b2: Go dataplane manager and control publication (125 files)

Batch-list SHA-256: `b66de7832e533264f1452a4eff6ecf82bf0071b3f6de954572473799ece20fe4`.

`negative` means the file was inspected and no credible non-duplicate finding survived. Each module note records all five required review dimensions: correctness/security/fail-open behavior; memory safety/concurrency/truncation/leaks; vSRX feature completeness; performance/latency; and modularity/test gaps.

### Formatting, host admission, injection, and interface modeling

Dimensions: correctness/security checked default-deny host admission, family/protocol constraints, tuple validation, and interface identity; memory/concurrency checked bounded parsing and immutable snapshot values; vSRX parity checked Junos host-service semantics and physical/unit inheritance; performance checked grouping and lookup work stays off packet hot paths; modularity/tests checked formatter, classifier, and interface-builder boundaries plus negative cases.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/format/wireguard.go` | WireGuard status formatting | negative | Rendering clamps ages, distinguishes unavailable/never state, and cannot alter runtime state. |
| `pkg/dataplane/userspace/format/wireguard_test.go` | WireGuard formatter tests | negative | Summary/detail, reason tables, empty keys, and handshake-age clamps are covered. |
| `pkg/dataplane/userspace/host_inbound_classify.go` | Host-inbound classifier | negative | Unconfigured, family-mismatched, and non-admitted traffic remains denied; admitting token is explicit. |
| `pkg/dataplane/userspace/host_inbound_classify_3627_test.go` | Classifier tests | negative | Full admit, ident-reset deny, no-stanza deny, family gate, and token reporting are pinned. |
| `pkg/dataplane/userspace/host_inbound_per_iface_3362_test.go` | Per-interface host views | negative | Interface overrides are scoped and unioned with zone services without cross-interface widening. |
| `pkg/dataplane/userspace/host_inbound_phys_unit_3720_test.go` | Physical/unit host views | negative | Physical and unit overrides union deterministically without cross-zone leakage. |
| `pkg/dataplane/userspace/host_inbound_protocols_all_4411_test.go` | Host protocol wildcard | negative | `protocols all` does not become an unrestricted host admit. |
| `pkg/dataplane/userspace/host_inbound_unzoned_4420_test.go` | Unzoned host addresses | negative | Unzoned local addresses remain explicit and family-correct. |
| `pkg/dataplane/userspace/host_inbound_view_grouping_3721_test.go` | Host-view grouping | negative | Equivalent sets merge independent of order; distinct enforcement sets remain separate; benchmark exists. |
| `pkg/dataplane/userspace/inject.go` | Diagnostic packet injection | negative | Wire emission is protocol-version gated, tuple/family coherent, and packet length bounded before IPC. |
| `pkg/dataplane/userspace/inject_test.go` | Injection tests | negative | Missing tuple protocol/IP, cross-protocol, malformed length, and legacy metadata fail closed. |
| `pkg/dataplane/userspace/interfaces.go` | Interface snapshot builder | negative | Linux names, parent/child identity, deterministic synthetic logical IDs, and configured addresses remain coherent. |
| `pkg/dataplane/userspace/interfaces_test.go` | Interface-name drift test | negative | Kernel-name resolution stays aligned with snapshot Linux naming. |
| `pkg/dataplane/userspace/junos_host_deny.go` | Junos host-deny lowering | negative | Host-deny entries preserve family/L4 constraints and do not broaden malformed rules. |
| `pkg/dataplane/userspace/junos_host_netdev_parity_test.go` | Host netdev parity | negative | Zone netdev selection matches the published snapshot. |
| `pkg/dataplane/userspace/junos_host_policy_3019_test.go` | Junos host policy parity | negative | Published host-policy rule fields preserve the configured rule. |
| `pkg/dataplane/userspace/junos_ping_icmp_3020_test.go` | Junos ping parity | negative | Ping maps to family-specific echo-request while `icmp-all` remains unconstrained. |

### Legacy adapter and process/link lifecycle

Dimensions: correctness/security checked adapter delegation, helper start/stop, control-map gating, worker rebind, and fail-closed transitions; memory/concurrency checked mutex ownership, goroutine cancellation, process waits, and UMEM/XSK lifetime ordering; vSRX parity checked link-cycle behavior used by RETH; performance checked status cadence and avoided packet-path work; modularity/tests checked legacy/runtime boundaries and injected link-cycle ordering, exposing A6-b2-F002's missing failure-path contract.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/legacy_dataplane.go` | Legacy runtime adapter | negative | Optional interfaces delegate to the userspace manager and nil backends fail safely. |
| `pkg/dataplane/userspace/legacy_dataplane_batchclear_5096_test.go` | Batch/clear adapter tests | negative | Batch and counter-clear operations route to helper-backed implementations. |
| `pkg/dataplane/userspace/legacy_dataplane_test.go` | Adapter contract tests | negative | Optional surfaces, nil safety, and cursor iteration preserve caller contracts. |
| `pkg/dataplane/userspace/link_cycle_test.go` | Link-cycle tests | A6-b2-F002 | Happy-path ordering proves ctrl is zero before `stop_workers`, but no lookup/update-failure case exists. |
| `pkg/dataplane/userspace/process.go` | Helper process lifecycle | A6-b2-F002 | Helper shutdown must not proceed while XDP can still redirect to its dead XSK sockets. |
| `pkg/dataplane/userspace/process_control.go` | Control socket | negative | Request size/deadline bounds, JSON framing, EOF diagnostics, and response errors are surfaced. |
| `pkg/dataplane/userspace/process_linkcycle.go` | Link-cycle control | A6-b2-F002 | Mandatory ctrl disable/rollback writes must be observable before worker stop or rebind. |
| `pkg/dataplane/userspace/process_napi.go` | NAPI bootstrap | negative | Probe scheduling is bounded/cold-path and does not hold resources across process teardown. |
| `pkg/dataplane/userspace/process_status.go` | Status reconciliation loop | A6-b2-F003 | Status-loop startup/retry must survive post-ack reconciliation failures, including standalone HA cleanup. |

### Manager compile, HA, publication, and observability

Dimensions: correctness/security checked snapshot atomicity, protocol gates, HA ownership, forwarding arm state, session sync, counters, and post-publish retries; memory/concurrency checked manager/session locks, copied snapshots, atomics, cancellation, and bounded control work; vSRX parity checked CoS, NAT, screens, tunnels, fabric, policy scheduler, and HA behavior; performance checked one-second status traffic, bulk counters, and generation-only updates; modularity/tests checked runtime controller boundaries and failure injection, producing A6-b2-F001, F003, and F004.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/manager.go` | Manager lifecycle/API | negative | Runtime interfaces, locks, start/close, and apply-result ownership remain coherent. |
| `pkg/dataplane/userspace/manager_capabilities_test.go` | Capability gates | negative | Unsupported semantic gaps and protocol requirements are classified without accidental fail-open. |
| `pkg/dataplane/userspace/manager_compile.go` | Full snapshot compile/apply | A6-b2-F001, A6-b2-F003 | Interface attachments and auxiliary HA state must commit atomically with the acknowledged snapshot and retain retry debt. |
| `pkg/dataplane/userspace/manager_cos_test.go` | CoS snapshot tests | negative | Policer, scheduler, classifier, rewrite, exact-rate, buffer, surplus, and equal-flow fields round-trip. |
| `pkg/dataplane/userspace/manager_counters_test.go` | Counter reconciliation tests | negative | Per-binding totals and reset-safe deltas feed global/screen/NAT counters without wrap inflation. |
| `pkg/dataplane/userspace/manager_coupling_test.go` | Runtime boundary tests | negative | Userspace manager does not embed or expose the retired legacy dataplane contract. |
| `pkg/dataplane/userspace/manager_fabric_test.go` | Fabric snapshot test | A6-b2-F004 | Snapshot shape is covered, but helper publication failure and retry are not. |
| `pkg/dataplane/userspace/manager_flow_test.go` | Flow snapshot tests | negative | Timeouts, ALG flags, and export settings retain configured meaning. |
| `pkg/dataplane/userspace/manager_generation.go` | FIB generation/neighbor bump | negative | Generation bump errors surface and neighbor cache advances only after acknowledged replacement. |
| `pkg/dataplane/userspace/manager_ha.go` | HA/fabric/session synchronization | A6-b2-F003, A6-b2-F004 | Standalone must clear stale HA groups with retry; live fabric refresh failures must reach callers. |
| `pkg/dataplane/userspace/manager_ha_test.go` | HA manager tests | negative | Activation, liveness, seeded RGs, watchdog throttle, busy bindings, and stop reset are covered; transient standalone clear is absent. |
| `pkg/dataplane/userspace/manager_interfaces_test.go` | Interface snapshot tests | negative | Local addresses, filters, logical VLAN IDs, fabric parents, aliases, and tunnel exclusion are deterministic. |
| `pkg/dataplane/userspace/manager_mirrors_test.go` | Mirror snapshot tests | negative | Scope, duplicates, invalid rates, and missing output interfaces are handled conservatively. |
| `pkg/dataplane/userspace/manager_misc_test.go` | Misc manager tests | negative | RST suppression retry and zero-MAC formatting stay bounded. |
| `pkg/dataplane/userspace/manager_nat_test.go` | NAT manager tests | negative | Pool fields, unsafe modes, helper counter clear, and cache durability are preserved. |
| `pkg/dataplane/userspace/manager_neighbor.go` | Neighbor publication/index | negative | Index contains only publishable neighbors and advances only after helper acknowledgement. |
| `pkg/dataplane/userspace/manager_overlay.go` | Route-overlay publication | negative | Overlay hash/diff and snapshot baseline advance only after successful publish. |
| `pkg/dataplane/userspace/manager_policy_test.go` | Policy manager tests | negative | Zone/global/address/application policies and scheduler inactive bits remain representable and retryable. |
| `pkg/dataplane/userspace/manager_policycounters_test.go` | Policy-counter manager tests | negative | Scheduled rule identity, helper/status IPC, cache reset, and re-add continuity are covered. |
| `pkg/dataplane/userspace/manager_republish_3780_test.go` | Scheduler republish tests | negative | Failed publish returns error and retains generation; helperless path is intentionally converged. |
| `pkg/dataplane/userspace/manager_routes_test.go` | Route manager tests | negative | Route family normalization and connected-prefix inclusion are pinned. |
| `pkg/dataplane/userspace/manager_screens_test.go` | Screen manager tests | negative | Profile capabilities, thresholds, alarm/drop semantics, ordering, advanced fields, and missing refs are covered. |
| `pkg/dataplane/userspace/manager_sessionsync_snapshot_5007_test.go` | Session-sync snapshot consistency | negative | Pair resolution uses one coherent snapshot generation. |
| `pkg/dataplane/userspace/manager_sessionsync_test.go` | HA session-sync tests | negative | Byte order, both NAT legs, log/policy metadata, NAT64 v4, tunnel identity, generation, and failure health are covered. |
| `pkg/dataplane/userspace/manager_snapshot_test.go` | Snapshot identity/hash tests | negative | Summary counts and content hash ignore only volatile fields and change on forwarding content. |
| `pkg/dataplane/userspace/manager_status.go` | Status/query operations | negative | Status, delta drain/export, and inject calls serialize on the intended control surfaces and return helper errors. |
| `pkg/dataplane/userspace/manager_testhelpers_test.go` | Manager test fixtures | negative | BPF-map injection helpers preserve ABI and skip cleanly when unavailable. |
| `pkg/dataplane/userspace/manager_tunnels_test.go` | Tunnel snapshot tests | negative | GRE/WireGuard endpoints, transport tables, RG derivation, source/destination requirements, and private-key channel contract are covered. |
| `pkg/dataplane/userspace/manager_worker_arm_5134.go` | Deferred worker-arm debt | negative | Failed post-MAC arm remains durable and retryable until helper convergence. |
| `pkg/dataplane/userspace/manager_worker_arm_5134_test.go` | Worker-arm debt tests | negative | Helper-down retention, already-armed settlement, and recovery publication are covered. |

### BPF shim map publication

Dimensions: correctness/security checked ctrl, binding, heartbeat, ingress, local-address, and interface-NAT map fail-closed ordering; memory/concurrency checked map bounds, uint flattening, iteration, and manager lock ownership; vSRX parity checked local/NAT address reachability; performance checked bounded array work and watchdog cadence; modularity/tests checked map-name registry parity, capacity guards, and partial-enumeration behavior.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/maps.go` | Map-name registry | negative | Retained shim map names are centralized and type/ABI ownership stays explicit. |
| `pkg/dataplane/userspace/maps_decouple_test.go` | Registry decoupling tests | negative | Literal aliases, concatenation bypasses, drift shapes, and legacy-loader parity are rejected. |
| `pkg/dataplane/userspace/maps_sync.go` | Shim map synchronization | negative | New classifier entries publish before stale removal, cap violations fail closed, and READY requires helper liveness. |
| `pkg/dataplane/userspace/maps_sync_addrlist_prune_3924_test.go` | Address enumeration tests | negative | Failed address enumeration suppresses prune; complete enumeration removes stale rows. |
| `pkg/dataplane/userspace/maps_sync_cap_test.go` | Map cap/fail-close tests | negative | Ifindex caps, ctrl fail-close, add-before-remove, lookup failure, and watchdog guards are covered. |
| `pkg/dataplane/userspace/maps_sync_heartbeat_slots_4572_test.go` | Heartbeat capacity test | negative | Worker-derived zeroing is clamped to the real map capacity. |

### Mirrors and NAT publication

Dimensions: correctness/security checked rule expansion, named-address resolution, L4 bounds, exemption semantics, deterministic mapping, scope precedence, and fail-closed malformed content; memory/concurrency checked bounded expansion and immutable slices; vSRX parity checked source/destination/static/NPTv6/NAT64 behavior and per-uplink scope; performance checked no unbounded port-range expansion; modularity/tests checked builder separation and extensive negative cases.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/mirrors.go` | Mirror snapshot builder | negative | Mirror direction, rates, interface scope, and output identity remain explicit. |
| `pkg/dataplane/userspace/named_port_caseinsensitive_3372_test.go` | Named-port policy/NAT test | negative | Mixed-case named ports do not split commit validation from apply behavior. |
| `pkg/dataplane/userspace/nat.go` | Shared NAT lowering | negative | Protocol/application/port expansion is bounded and malformed selectors cannot become wildcards. |
| `pkg/dataplane/userspace/nat64.go` | NAT64 snapshot builder | negative | Prefix/pool/deterministic fields and fragment-header policy remain explicit. |
| `pkg/dataplane/userspace/nat64_deterministic_4559_test.go` | Deterministic NAT64 tests | negative | IPv6 prefix constraints and absent/deferred modes are covered. |
| `pkg/dataplane/userspace/nat64_frag_header_test.go` | NAT64 fragment-header tests | negative | Configured and default no-v6-fragment-header states reach the wire. |
| `pkg/dataplane/userspace/nat_address_name_failclosed_3425_test.go` | Empty address-set tests | negative | Empty named source/destination sets reject rather than widening to any. |
| `pkg/dataplane/userspace/nat_dest_address_name_3229_test.go` | Destination address names | negative | Named/literal unions resolve; unknown names fail closed for SNAT and DNAT. |
| `pkg/dataplane/userspace/nat_dest_prefix_3164_test.go` | DNAT prefix tests | negative | Prefix destinations and host/prefix classification preserve match scope. |
| `pkg/dataplane/userspace/nat_destination.go` | Destination NAT builder | negative | Applications, protocol/ports, pools, exemptions, address names, and counter IDs retain conjunctive scope. |
| `pkg/dataplane/userspace/nat_dnat_app_dport_3857_test.go` | DNAT app/dport tests | negative | Explicit destination ports override app ports; invalid values reject. |
| `pkg/dataplane/userspace/nat_dnat_app_empty_3434_test.go` | Empty application tests | negative | Undefined/empty app references fail closed while absent app remains wildcard. |
| `pkg/dataplane/userspace/nat_dnat_app_match_3437_test.go` | DNAT application tests | negative | Source ports and ICMP type/code survive expansion; invalid-only app content rejects. |
| `pkg/dataplane/userspace/nat_dnat_match_dport_3446_test.go` | DNAT destination-port tests | negative | Zero, nonnumeric, and out-of-range ports reject; valid members survive mixed input. |
| `pkg/dataplane/userspace/nat_dnat_off_3844_test.go` | DNAT exemption test | negative | `off` publishes an explicit exemption rather than deleting match semantics. |
| `pkg/dataplane/userspace/nat_dnat_pool_3450_test.go` | DNAT pool tests | negative | Invalid pool port/address/CIDR rejects; valid host pool emits. |
| `pkg/dataplane/userspace/nat_dnat_port_range_3449_test.go` | DNAT range tests | negative | Wide/full ranges stay compact and discrete/range mixes preserve all members. |
| `pkg/dataplane/userspace/nat_feed_overlay_3303_test.go` | Dynamic-feed NAT tests | negative | Feed and static address-book members union for all source/destination directions. |
| `pkg/dataplane/userspace/nat_l4_match_3429_test.go` | SNAT L4 tests | negative | Invalid protocol/port/app content cannot collapse into a wildcard; valid members remain. |
| `pkg/dataplane/userspace/nat_match_multivalue_3431_test.go` | NAT multivalue tests | negative | Every protocol/application member expands without first-value truncation. |
| `pkg/dataplane/userspace/nat_nptv6.go` | NPTv6 snapshot builder | negative | Prefix lengths and translated prefixes are carried without narrowing. |
| `pkg/dataplane/userspace/nat_per_uplink_test.go` | Per-uplink NAT tests | negative | Zones, counter IDs, source constraints, multiple destinations, and non-TCP/UDP rules persist. |
| `pkg/dataplane/userspace/nat_reversed_port_range_3726_test.go` | Reversed-range tests | negative | Reversed ranges reject; equal endpoints retain exact-port semantics. |
| `pkg/dataplane/userspace/nat_scope_3096_test.go` | NAT scope tests | negative | Source, destination, and static NAT carry configured interface/zone scope. |
| `pkg/dataplane/userspace/nat_scope_precedence_4161_test.go` | NAT scope precedence | negative | More-specific scope wins independent of declaration order; same-tier order is stable. |
| `pkg/dataplane/userspace/nat_source.go` | Source NAT builder | negative | Pools, deterministic mode, persistent flags, L4 selectors, scopes, and counter identity remain fail closed. |
| `pkg/dataplane/userspace/nat_source_address_name_2416_test.go` | Source address names | negative | SNAT/DNAT source names and literal unions resolve; unknown names reject. |
| `pkg/dataplane/userspace/nat_source_deterministic_4559_test.go` | Deterministic SNAT tests | negative | IPv4 deterministic mapping publishes; unsupported IPv6 remains explicitly deferred. |
| `pkg/dataplane/userspace/nat_source_pool_port_3906_test.go` | SNAT pool-port tests | negative | Configured/no-translation/default port ranges preserve exact wire semantics. |
| `pkg/dataplane/userspace/nat_static.go` | Static NAT builder | negative | Bidirectional static mappings preserve family and scoped identity. |
| `pkg/dataplane/userspace/natcounters.go` | NAT counter adapter | negative | Counter IDs and helper cumulative values map without index drift or silent widening. |

### Neighbor snapshot construction

Dimensions: correctness/security checked publishability, NUD state normalization, interface scoping, and replacement semantics; memory/concurrency checked bounded netlink materialization and immutable output; vSRX parity checked ARP/NDP/router/link-local metadata; performance checked sorted cold-path rebuilds; modularity/tests checked the hard-coded netlink boundary. A failed-dump-as-authoritative candidate was suppressed as the same root as tracked #2919.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/neighbors.go` | Kernel neighbor snapshot builder | negative | Only configured interfaces and canonical family/state/MAC data enter replacement snapshots; known failed-dump root suppressed. |

### Policy lowering, representability, scheduling, and counters

Dimensions: correctness/security checked address/application expansion, excluded members, stable IDs, scheduler inactivity, reject reasons, and unrepresentable-content sentinels; memory/concurrency checked bounded recursive expansion, cycle handling, copies, and counter-lock release; vSRX parity checked zone/global/default policy semantics and reject behavior; performance checked precomputed IDs/indexes and bulk counter resolution; modularity/tests checked lowering stages and namespace boundaries.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/lenient_keep_armed_3261_test.go` | Lenient representability tests | negative | Unrepresentable content emits deny sentinel without disarming; cycles, feeds, empty sets, and explicit any are distinguished. |
| `pkg/dataplane/userspace/nested_app_set_policy_test.go` | Nested application-set test | negative | Recursive app sets expand without losing members. |
| `pkg/dataplane/userspace/policies.go` | Policy snapshot orchestration | negative | Zone/global order and per-rule identity remain deterministic. |
| `pkg/dataplane/userspace/policies_addrbook.go` | Address-book expansion | negative | Names, feeds, exclusions, cycles, empties, and content IDs fail closed and remain bounded. |
| `pkg/dataplane/userspace/policies_ids.go` | Policy ID assignment | negative | Rule spans and stable runtime/counter IDs do not collide across sets. |
| `pkg/dataplane/userspace/policies_lower.go` | Rule lowering | negative | Address/app/L4 constraints, action, logging, timeout, and scheduler state reach one coherent rule. |
| `pkg/dataplane/userspace/policies_reject.go` | Rejection diagnostics | negative | Scope/object reasons name the actual unrepresentable content. |
| `pkg/dataplane/userspace/policies_representable.go` | Representability gate | negative | Unknown protocols/ports/apps and semantic gaps cannot be treated as supported. |
| `pkg/dataplane/userspace/policies_scheduler.go` | Scheduler state | negative | Missing/inactive scheduler state is explicit and copied safely. |
| `pkg/dataplane/userspace/policy_global_zone_3148_test.go` | Global policy zone context | negative | Global rules retain source/destination zone context. |
| `pkg/dataplane/userspace/policy_match_excluded_test.go` | Excluded-match test | negative | Exclusion bits survive snapshot publication. |
| `pkg/dataplane/userspace/policy_namespace_3143_3145_test.go` | Policy namespace tests | negative | Nil slots, span accumulation, max-rules caps, exact fills, and cross-set boundaries preserve IDs. |
| `pkg/dataplane/userspace/policy_reject_reasons_3376_test.go` | Rejection reason tests | negative | Zone/global scope and rejected object rendering are actionable. |
| `pkg/dataplane/userspace/policy_runtime_ids_3063_test.go` | Runtime policy ID test | negative | Runtime IDs match snapshot IDs. |
| `pkg/dataplane/userspace/policycounters.go` | Policy counter adapter | negative | Counter resolution handles scheduler churn and releases manager lock before external work. |
| `pkg/dataplane/userspace/policycounters_bulk_test.go` | Bulk policy-counter tests | negative | Bulk/per-policy parity, one-time indexing, and lock release are covered. |

### Wire protocol and DTOs

Dimensions: correctness/security checked JSON field names/types/defaults, protocol gates, null collections, and fail-closed unsupported sentinels; memory/concurrency checked bounded DTO conversion and copies; vSRX parity checked all exposed status/counter/CoS/session fields; performance checked wire payload shape and no packet-path conversion; modularity/tests checked Go/Rust schema boundaries and backward compatibility.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/protocol.go` | Go control/snapshot schema | negative | Snapshot, status, session, HA, CoS, NAT, and diagnostic fields retain types, defaults, and compatibility tags. |
| `pkg/dataplane/userspace/protocol_failopen_2124_test.go` | Protocol fail-open tests | negative | Unknown protocol/malformed ports create unsupported sentinels and pre-publish disarm. |
| `pkg/dataplane/userspace/protocol_null_collections_2214_test.go` | Null-collection tests | negative | Empty required collections marshal as arrays, never `null`. |
| `pkg/dataplane/userspace/protocol_test.go` | Protocol round-trip suite | negative | Binding, counters, CoS, HA, event stream, flow capacity, latency, and refusal telemetry round-trip/back-compat are covered. |

### Routes and runtime overlay

Dimensions: correctness/security checked family/table canonicalization, next-table recursion, rule-list errors, selector widening, dedupe, and overlay transactionality; memory/concurrency checked copied overlays and bounded sorting; vSRX parity checked rib-group/next-table/ECMP/preference behavior; performance checked deterministic total ordering and duplicate-publish hashing; modularity/tests checked netlink rule seams. The selector-loss candidate was suppressed as the same root as tracked #4479.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/route_overlay_test.go` | Route-overlay tests | negative | Whole-entry replacement, content hash, publish success/no-helper, and failed-publish baseline retention are covered. |
| `pkg/dataplane/userspace/routes.go` | Route snapshot builder | negative | Families, tables, ECMP, preference, overlays, and rule-list errors are deterministic; known selector-widening root suppressed. |
| `pkg/dataplane/userspace/routes_dedupe_3770_test.go` | Route dedupe/sort tests | negative | Discard/connected/preference distinctions and total order are retained. |
| `pkg/dataplane/userspace/routes_family_normalize_4423_test.go` | Route family normalization | negative | VRF table suffix changes preserve the routing-instance name. |
| `pkg/dataplane/userspace/routes_fib_metadata_test.go` | FIB metadata tests | negative | Preference, all ECMP next hops, and interface routing-instance mappings reach snapshots. |
| `pkg/dataplane/userspace/routes_ipv6_nexttable_3768_test.go` | IPv6 next-table test | negative | IPv6 rule leaks recurse into `.inet6.0`, not `.inet.0`. |
| `pkg/dataplane/userspace/routes_pbr_priority_4479_test.go` | PBR-band suppression tests | negative | Known PBR priority band is skipped and pure next-table band remains ingested. |
| `pkg/dataplane/userspace/routes_ribgroup_leak_3876_test.go` | Rib-group leak tests | negative | Per-prefix rules are mirrored; destination-less blanket rules are skipped. |
| `pkg/dataplane/userspace/routes_rulelist_3772_test.go` | Rule-list/error tests | negative | Netlink errors abort, malformed overlays skip, and successful empty lists remain valid. |

### Backend-neutral runtime adapters

Dimensions: correctness/security checked lossless status/session adaptation and HA controller error contracts; memory/concurrency checked copied slices and context handling; vSRX parity checked session and fabric metadata exposure; performance checked adapters remain cold-path; modularity/tests checked neutral interfaces against direct userspace paths. The unused neutral session-delta metadata concern was refuted; fabric error suppression survives as A6-b2-F004.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/runtime_delta.go` | Neutral session-delta adapter | negative | Current neutral schema is copied consistently; production HA still uses the richer direct `SessionDeltaInfo` path. |
| `pkg/dataplane/userspace/runtime_delta_test.go` | Runtime adapter/controller tests | A6-b2-F004 | Fabric update order is tested, but the void `SyncFabricState` fake cannot assert helper publication errors. |

### A6-b3: Go dataplane manager and control publication (38 files)

Batch-list SHA-256: `7de676cd59225c2092afde0c7d695a0622b605e152daa880805cea4052941db4`.

### Snapshot policy, screen, NAT, and interface selection

Review dimensions: correctness/security covered policy scope, NAT narrowing, screen defaults, neighbor publication, and binding selection; memory/concurrency covered bounded slice/map construction and immutable snapshot ownership; vSRX parity covered static-NAT port scope, three-color defaults, and zone-local address books; performance covered deterministic sorting and control-plane-only allocations; modularity/test coverage checked wire SSOTs and malformed/old-helper negative cases. Findings remain where malformed state widens NAT and where additive policy skew widens a deny.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/scoped_global_zoneset_4626_test.go` | Global-policy wire scope | A6-b3-F002 | A multi-zone scope must remain fail-closed when plural fields meet a singular-only helper; current test instead blesses first-zone degradation. |
| `pkg/dataplane/userspace/screens.go` | Screen snapshot and SYN-cookie key | negative | Sorted emission, bounded `uint32` publication, missing-profile signaling, secret derivation/redaction, and nil handling were traced; overflow is guarded in config and known missing-profile pass behavior is deduped. |
| `pkg/dataplane/userspace/snapshot_allowlist_test.go` | AF_XDP bind allowlist | negative | Only zoned, non-management, non-tunnel bind targets survive; VLAN units use the parent SSOT and empty/error cases do not broaden the allowlist. |
| `pkg/dataplane/userspace/snapshot_neighbors_1197_test.go` | Neighbor publication/dedup | negative | Invalid IP/MAC/ifindex and unusable NUD states are excluded; MAC changes/removals perturb forwarding equality while harmless NUD churn does not. |
| `pkg/dataplane/userspace/static_nat_mapped_port_2491_test.go` | Static-NAT port wire | A6-b3-F001 | Invalid configured ports must remove or never-match the rule, not serialize as wildcard zero; the test currently asserts the widening representation. |
| `pkg/dataplane/userspace/static_nat_source_address_3435_test.go` | Static-NAT source constraint | negative | Plural source constraints and singular fallback reach Rust; a genuinely absent constraint alone means match-any, while malformed nonempty lists fail closed downstream. |
| `pkg/dataplane/userspace/three_color_default_4535_test.go` | Three-color policer capability | negative | Unspecified mode defaults to supported color-blind behavior; explicit unsupported color-aware mode disarms forwarding rather than bypassing enforcement. |
| `pkg/dataplane/userspace/zone_local_addressbook_3061_test.go` | Policy address-book lowering | negative | From/to zone-local precedence is directional, global fallback is scoped, and no address value leaks across zones. |

### Tunnels, wire encoding, bootstrap, and shim behavior

Review dimensions: correctness/security covered tunnel identity, family/table selection, WG key/peer transport, degraded XDP verdicts, and JSON typing; memory/concurrency covered immutable peer copies, bounded summaries, unsafe test seams, and object lifetimes; vSRX parity covered tunnel TTL, local-control handling, and WG teardown; performance covered deterministic cold-path sorting and per-CPU fallback counters; modularity/test coverage checked Go/Rust wire symmetry and loader boundaries. The apparent WG IPv6 `inet.0` mismatch is corrected by Rust `canonical_route_table` and was dropped.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/tunnels.go` | Tunnel endpoint publication | negative | Stable IDs, deterministic peer ordering, TTL defaulting, WG family selection, collision drop, and successful-publish-only transition logging were traced through Rust hydration/FIB lookup. |
| `pkg/dataplane/userspace/tunnels_test.go` | Tunnel regression suite | negative | Removal, multi-unit WG singleton emission, ID stability, collision handling, TTL, peer association, and deterministic JSON are covered; IPv6 table canonicalization is covered Rust-side. |
| `pkg/dataplane/userspace/userspace_boot_canary_test.go` | Runtime adapter bootstrap | negative | Both direct and registry boot paths return the legacy/runtime adapter shape; no nil or interface-surface loss survives. |
| `pkg/dataplane/userspace/wg_status_test.go` | WG status wire | negative | Identity, peer/local key separation, all counters, absent-field compatibility, and omission of empty status are pinned without private-key exposure. |
| `pkg/dataplane/userspace/wire_uint8list.go` | Numeric byte-list JSON | negative | Marshal never base64-encodes; unmarshal rejects range/type errors and allocations occur only on control-plane decode. |
| `pkg/dataplane/userspace/wire_uint8list_test.go` | Wire graph regression suite | negative | Typed DSCP/802.1p arrays, legacy decode, raw-byte graph scanning, and full-config request encoding agree with Rust `Vec<u8>`. |
| `pkg/dataplane/userspace/xdp_shim_decouple_test.go` | Retained XDP steering shim | negative | Disabled/not-ready transit drops, local/ARP/NDP control passes, CPU-map use, liveness fallback, per-CPU counters, and packet construction bounds were checked; no credible unknown-EtherType forwarding path was established. |
| `pkg/dataplane/userspace/shim_loader_boundary_test.go` | Userspace loader ownership | negative | Startup/compile route through retained shim entry points and avoid legacy XDP/TC object loaders; AST-based guard is test-only and allocates off path. |

### Zone publication, host-inbound enforcement, quarantine, and counters

Review dimensions: correctness/security covered deterministic zone ownership, kernel/Rust host-inbound parity, collision quarantine, observability, and counter clear semantics; memory/concurrency covered map ownership, lock ordering, sparse status, and bounded collision walks; vSRX parity covered default-deny, lifelines, VRRP VIPs, per-interface overrides, and TCP RST; performance covered sorted config-time walks and avoidance of packet-path work; modularity/test coverage checked shared canonical signatures and quarantine/counter negative cases. One exact-unit override path bypasses the existing cross-zone guard, and counter clear is not atomic with the status poll.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace/zone_counters_status_test.go` | Zone-counter status mirror | A6-b3-F005 | Absolute updates and wire round-trip work, but the suite does not cover a poll between local clear and helper clear or deletion on sparse absence. |
| `pkg/dataplane/userspace/zonecounters.go` | Zone-counter clear IPC | A6-b3-F005 | Local offsets and helper totals must cross one serialization boundary; clearing offsets before `m.mu` permits old totals to be reinserted and survive a successful clear. |
| `pkg/dataplane/userspace/zones.go` | Interface-to-zone map | A6-b3-F003 | Sorted first-writer ownership is deterministic, but it must also constrain every host-inbound override merge on tolerant multi-owner state. |
| `pkg/dataplane/userspace/zones_addressless_3698_test.go` | Addressless-zone observability | negative | Zone-level transient fail-open windows, lifeline/no-interface exclusions, and self-heal are correctly signaled; the underlying #3698 gap is already tracked and suppressed. |
| `pkg/dataplane/userspace/zones_addressless_iface_3710_test.go` | Addressless interface/family observability | negative | DHCP/DHCPv6 family granularity, low-noise exclusions, sorting, and self-heal are covered; the known #3710 window is deduped. |
| `pkg/dataplane/userspace/zones_ambiguous_3718_test.go` | Host-local ambiguity signal | negative | Differing admission sets on one destination are reported, identical sets are suppressed, and VIPs are included; the destination-only #3718 issue is already tracked. |
| `pkg/dataplane/userspace/zones_collision_3719_test.go` | Stable-zone-ID quarantine tests | negative | Zones/interfaces/policies, singular/plural global scopes, diagnostics, and no-collision behavior are scrubbed deterministically; residual screen/NAT names are inert after interface unzoning/name matching. |
| `pkg/dataplane/userspace/zones_host_inbound.go` | Kernel nft host-inbound views | negative | Default-deny, lifeline exclusion, static/live/VIP address resolution, canonical token grouping, and unzoned catch-all behavior were traced; known addressless/ambiguity gaps are signaled. |
| `pkg/dataplane/userspace/zones_host_inbound_test.go` | Host-inbound parity tests | negative | Rust and nft no-stanza default-deny, nil-zone behavior, learned addresses, VRRP VIPs, and configured lifelines are covered without packet-path allocations. |
| `pkg/dataplane/userspace/zones_observability.go` | Host-inbound diagnostics | negative | Zone/interface/family and ambiguous-address reports derive from enforcement views, sort deterministically, and avoid false IPv6/lifeline reports. |
| `pkg/dataplane/userspace/zones_override.go` | Per-interface host-inbound override merge | A6-b3-F003 | Additive physical/unit behavior is correct for one owner, but the exact-unit branch merges a later conflicting zone without consulting `zoneByIface`. |
| `pkg/dataplane/userspace/zones_quarantine.go` | Zone-ID collision quarantine | negative | Later colliders are removed, interfaces unzoned, all policy zone fields scrubbed, and diagnostics sorted; no surviving non-policy row can match the quarantined zone at runtime. |
| `pkg/dataplane/userspace/zones_snapshot.go` | Zone wire snapshots | negative | Stable IDs, unconditional host-inbound default-deny, token normalization, nil-zone handling, and TCP-RST publication are deterministic and bounded. |
| `pkg/dataplane/userspace/zones_stable_id_3704_test.go` | Wire/compiler/HA zone-ID parity | negative | Stable name hashes remain invariant across zone-set edits and agree with display and per-RG ownership namespaces. |
| `pkg/dataplane/userspace/zones_tcp_rst_3071_test.go` | Zone TCP-RST wire | negative | Enabled state crosses the exact JSON field and false remains omitted; old-helper degradation is silent drop, not a permit bypass. |

### Top-level shim verification and legacy counter surfaces

Review dimensions: correctness/security covered embedded-object parsing, production map ABI, verifier rejection, pin cleanup, watchdog writes, and stable-ID counter reads; memory/concurrency covered anonymous map lifetime, pin handles, cleanup continuation, per-CPU maps, and sparse offset locks; vSRX parity was not materially applicable beyond fail-closed startup; performance covered verify-only hash shrinking and bounded log tails; modularity/test coverage checked whether the verifier and production loader share the same map inventory. They do not for `dnat_table_v6`, producing A6-b3-F004.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/dataplane/userspace_shim_loader_test.go` | Shim map ABI/pin migration tests | A6-b3-F004 | Full ABI and live-pin checks cover listed `PinByName` maps and v4 DNAT, but no test mutates the production-replaced `dnat_table_v6` candidate spec. |
| `pkg/dataplane/userspace_xdp_rust.go` | Embedded shim object loader | negative | The exact embedded bytes are parsed through cilium/ebpf with errors wrapped; ownership remains with the returned spec. |
| `pkg/dataplane/verify_userspace_shim.go` | Build/deploy verifier | A6-b3-F004 | Copy-before-shrink, bounded verifier logs, and anonymous closure are correct, but anonymous `NewCollection` does not exercise all production map replacements. |
| `pkg/dataplane/verify_userspace_shim_test.go` | Verifier regression suite | A6-b3-F004 | Current artifact, shrink equivalence, ordering, and immutability are tested; production replacement compatibility for v6 DNAT is absent. |
| `pkg/dataplane/watchdog_test.go` | HA watchdog map API | negative | Missing-map failure is explicit and map updates fail on invalid indices; the nominal interface-compliance test is weak but no runtime defect survived. |
| `pkg/dataplane/zone_flood_counters_hide_test.go` | Sparse zone/flood read surface | negative | Large stable IDs never index dense arrays, populated zero is distinguishable from unavailable, and explicit clears remove offsets. |
| `pkg/dataplane/zoneid_stable_test.go` | Compiler zone-ID assignment | negative | Add/remove edits preserve IDs and assignment matches the stable-ID SSOT; collision rejection/quarantine is handled at surrounding gates. |

### A7-b1: Daemon lifecycle and Linux host integration (125 files)

Batch-list SHA-256: `86838bdb7b373e39fbda5e9fb414e966f16912a5ba8a9f00f5d882ea2ec2a371`.

Dimension key: **C/S/F** = correctness, security, and fail-open behavior; **M/C/L** = memory safety, concurrency, truncation, and leaks; **vSRX** = relevant feature-parity check; **Perf** = performance/latency; **Mod/tests** = modularity, single-source-of-truth, and test-gap review. `negative` means no non-duplicate finding survived for that file.

### Core lifecycle, apply, bootstrap, and archival

| Path | Module/subsystem | Result | Invariant checked | C/S/F | M/C/L | vSRX | Perf | Mod/tests |
|---|---|---|---|---|---|---|---|---|
| `pkg/daemon/aggregator_callback_4964_test.go` | session reporting | A7-b1-F004 | one stable callback must target only the live aggregator | callback fencing checked | atomic pointer checked | N/A | event path stays allocation-neutral at dispatch | shutdown cancellation is not covered |
| `pkg/daemon/aggregator_flush_5313_test.go` | session reporting | A7-b1-F004 | replacement/disable must flush and retire the old window | config transitions covered | test cleanup cancels, but daemon shutdown does not | N/A | bounded top-K flush | missing Run-shutdown test |
| `pkg/daemon/api_bind_clamp_5127_test.go` | API lifecycle | negative | management API bind cannot escape the runtime loopback clamp | clamp is fail-closed | no lifetime leak found | N/A | startup-only | direct negative test present |
| `pkg/daemon/apply_ctx_cancel_test.go` | apply transaction | negative | signal cancellation aborts at coarse boundaries without letting client cancellation split a promoted apply | transactional boundary checked | semaphore/context ownership checked | N/A | no packet-path effect | boundary tests are specific and adequate |
| `pkg/daemon/apply_interface_reconcile_failclosed_5310_test.go` | interface apply | negative | interface reconcile errors reach the commit result | fail-closed join checked | no leak found | N/A | cold path | regression pins error threading |
| `pkg/daemon/apply_serialize_test.go` | apply transaction | negative | commit/apply pairs cannot interleave | serialization checked | weighted semaphore ownership checked | N/A | contention limited to commits | concurrent regression present |
| `pkg/daemon/archive_atomic_4621_test.go` | config archival | negative | staged archive is complete-or-absent and owner-only | secret snapshot handling checked | temp cleanup checked | N/A | archival off packet path | atomic-write regression present |
| `pkg/daemon/archive_config_3867_test.go` | config archival | negative | archive serializes current active DB state, not the boot file | stale-config path checked | per-transfer timeout checked | parity behavior retained | bounded by configured sites | active-state regression present |
| `pkg/daemon/archive_timer_4078_test.go` | config archival | negative | timer replacement stops the prior generation | state convergence checked | stop-channel lifecycle checked | N/A | one timer generation | timer transition tests present |
| `pkg/daemon/bootstrap.go` | safe bootstrap | negative | bootstrap preserves the management lifeline and does not publish forwarding before takeover | fail-closed stages checked; known #1922 items suppressed | rollback/cleanup paths checked | bootstrap parity reviewed | boot-only scans | helpers and tests align |
| `pkg/daemon/bootstrap_lifeline_nonpci_4815_test.go` | safe bootstrap | negative | lifeline identity works for non-PCI devices | non-PCI management safety checked | no leak | hardware parity relevant | boot-only | regression covers fallback identity |
| `pkg/daemon/bootstrap_rollback_test.go` | safe bootstrap | negative | failed takeover restores host and durable state | rollback checked | cleanup ordering checked | N/A | boot-only | fault-injection coverage present |
| `pkg/daemon/bootstrap_test.go` | safe bootstrap | negative | bootstrap route/address capture and takeover sequencing preserve reachability | fail-closed matrix checked | snapshots bounded | management parity reviewed | bounded host inventory scan | broad branch coverage present |
| `pkg/daemon/coalescence.go` | apply coalescing | negative | repeated notifications publish the newest state without unbounded work | stale generation excluded | mutex/channel ownership checked | N/A | coalesces burst work | single helper owns policy |
| `pkg/daemon/coalescence_test.go` | apply coalescing | negative | burst and stop transitions honor the coalescing contract | negative/positive cases checked | race-sensitive paths covered | N/A | bounded wakeups | tests match implementation |
| `pkg/daemon/commit_confirm_demote_4378_test.go` | confirmed commit/HA | negative | rollback/demotion cannot leave the local node forwarding the rejected config | fail-closed demotion checked | ordering checked | HA parity relevant | control path only | regression present |
| `pkg/daemon/compile_error_policy_test.go` | compile/apply policy | negative | malformed state cannot be promoted into enforcement | compile failures fail closed | no leak | parity validation reviewed | compile path only | failure matrix present |
| `pkg/daemon/compile_health_test.go` | health publication | negative | compile degradation is observable without claiming healthy enforcement | health truthfulness checked | atomic publication checked | N/A | low-frequency metrics | regression present |
| `pkg/daemon/config_arrival_naming_4179_test.go` | startup naming | negative | transient first-arrival naming failures preserve retry debt | errors retained | generation state checked | bare-metal parity relevant | startup-only | retry regression present |
| `pkg/daemon/config_sync_test.go` | HA config sync | negative | peer config is applied and acknowledged in transaction order | error propagation checked | synchronization checked | HA parity relevant | control path | sync matrix present |
| `pkg/daemon/configstore_helper_test.go` | test/config store | negative | helper creates isolated durable config state | no security bypass | cleanup scoped to temp dirs | N/A | test-only | helper behavior clear |
| `pkg/daemon/configsync_tail_error_test.go` | HA config sync | negative | tail reconcile errors survive sync-and-apply | fail-closed result checked | no lifetime issue | HA parity relevant | control path | regression present |
| `pkg/daemon/daemon.go` | daemon ownership/state | A7-b1-F004 | every long-lived feature loop needs an owned cancellation and join path | state guards reviewed | aggregator/IPsec loops lack shutdown ownership | N/A | no hot-path regression | ownership is fragmented across feature fields |
| `pkg/daemon/daemon_apply.go` | apply transaction | A7-b1-F001, A7-b1-F002, A7-b1-F003, A7-b1-F005 | committed config, Linux names, host files, and activation debt must converge atomically | four surviving transition failures | apply semaphore sound; feature lifetimes separate | RETH/Junos naming parity affected | cold apply path | duplicated name resolver and untested teardown edges |
| `pkg/daemon/daemon_apply_runtime_test.go` | dataplane apply | negative | runtime-only apply preserves commit result and overlay semantics | runtime errors checked | no ownership leak | userspace-only runtime checked | control socket calls bounded by apply | regression present |
| `pkg/daemon/daemon_archive_timer.go` | config archival | negative | exactly one periodic timer generation owns each schedule | stop/replacement checked | timer stopped on transition | N/A | one ticker, site-bounded fanout | explicit lifecycle helper |
| `pkg/daemon/daemon_cluster_bind.go` | HA socket binding | negative | cluster endpoints are parsed and bound to the intended family/VRF | malformed addresses rejected | no leak found | HA parity relevant | startup-only | parsing centralized enough |

### DDNS, DHCP, DNS, feeds, flow, and telemetry

| Path | Module/subsystem | Result | Invariant checked | C/S/F | M/C/L | vSRX | Perf | Mod/tests |
|---|---|---|---|---|---|---|---|---|
| `pkg/daemon/daemon_ddns.go` | DHCP DDNS | negative | only the owning node publishes lease-derived records and withdrawals converge | ownership gates checked | reconcile loop bounded/cancellable by manager | DDNS parity reviewed | periodic control work | state derivation is centralized |
| `pkg/daemon/daemon_ddns_scope_test.go` | DHCP DDNS | negative | scope changes withdraw only records no longer owned | stale-record cases checked | no race gap found | parity relevant | test-only | transition coverage present |
| `pkg/daemon/daemon_ddns_surface_a.go` | interface/router DDNS | negative | source selection, HA ownership, and negative states publish consistently | malformed/unowned states checked | reconcile generation guarded | parity relevant | bounded interfaces/providers | helper decomposition and tests adequate |
| `pkg/daemon/daemon_ddns_surface_a_test.go` | interface/router DDNS | negative | all source/ownership/provider states produce deterministic status | fail/skip matrix checked | concurrency seams exercised | parity relevant | test-only | broad table coverage present |
| `pkg/daemon/daemon_ddns_test.go` | DHCP DDNS | negative | lease updates and HA changes reconcile records without stale ownership | negative transitions checked | no leak | parity relevant | test-only | core transitions covered |
| `pkg/daemon/daemon_dhcp.go` | DHCP client/relay naming | A7-b1-F001 | a config logical-unit reference must resolve to the VLAN-ID kernel netdev | bare resolver preserves the wrong suffix for affected callers | manager lifetime otherwise bounded | tagged RETH parity affected | cold resolution path | duplicate resolver diverges from `ResolveKernelIfName` |
| `pkg/daemon/daemon_dhcp_filter_4647_test.go` | HA DHCP server | A7-b1-F001 | master-RG filtering must compare identical kernel names | equal unit/VLAN cases pass | no leak | HA DHCP parity affected | test-only | misses unit number != VLAN ID |
| `pkg/daemon/daemon_dhcp_lease_sync.go` | HA DHCP lease sync | negative | primary lease deltas/heartbeats converge standby state without unbounded queueing | ownership and expiry paths checked | loop/tickers use cluster context | HA parity relevant | bounded cadence and batches | state machine tested |
| `pkg/daemon/daemon_dhcp_lease_sync_test.go` | HA DHCP lease sync | negative | startup, heartbeat, and change-trigger publication preserve lease state | failure cases checked | cancellation covered | HA parity relevant | test-only | good transition coverage |
| `pkg/daemon/daemon_dhcp_leasesync_4647_test.go` | HA DHCP lease sync | negative | per-RG filtering uses active ownership | standby suppression checked | no race gap found | HA parity relevant | test-only | regression present |
| `pkg/daemon/daemon_dhcp_relay_gate_test.go` | DHCP relay | negative | backup RG cannot relay duplicate traffic | gate fails closed | state access synchronized | HA parity relevant | packet service gate is O(1) | regression present |
| `pkg/daemon/daemon_dhcprelay_reconcile_test.go` | DHCP relay | negative | enable/change/delete reconciles sockets and config | stale service teardown checked | manager stop/restart covered | parity relevant | commit-only | lifecycle tests present |
| `pkg/daemon/daemon_dns.go` | resolver host integration | negative | generated resolver state, symlinks, and systemd-resolved teardown converge | write/remove errors surfaced | no persistent goroutine | parity reviewed | apply-only | activation helpers and tests align |
| `pkg/daemon/daemon_dns_test.go` | resolver host integration | negative | boot repair, static/DHCP input, and teardown preserve a usable resolver | fail-closed cases checked | no leak | parity reviewed | test-only | broad state-transition coverage |
| `pkg/daemon/daemon_eventoptions_reconcile_test.go` | event options | negative | config changes replace/clear event actions | stale actions cleared | manager ownership checked | parity relevant | low-frequency | transition regression present |
| `pkg/daemon/daemon_fabric_monitor_4031_test.go` | HA fabric monitor | negative | subscription loss triggers resync and monitor shutdown is bounded | errors observable | channels/context checked | HA parity relevant | event-driven, bounded buffers | regression covers resubscribe |
| `pkg/daemon/daemon_feeds.go` | dynamic address feeds | negative | enabled bindings reconcile, removed bindings stop, snapshots remain immutable | stale-feed state checked | manager owns worker lifetimes | parity relevant | no packet-path fetches | direct manager contract checked |
| `pkg/daemon/daemon_feeds_reconcile_5036_test.go` | dynamic address feeds | negative | provider/config changes cannot reuse stale workers or snapshots | failure transitions checked | cancellation covered | parity relevant | test-only | regression present |
| `pkg/daemon/daemon_flow.go` | mgmt routes, link monitor, archival | negative | host routes, link-state publication, and archive staging converge independently | netlink/list failures handled | subscribers and transfer timeouts bounded | operational parity reviewed | no packet-path logging; scans event-driven | mixed module but helpers have focused tests |
| `pkg/daemon/daemon_flowexport.go` | NetFlow/IPFIX lifecycle | negative | exporter generations retire without accepting events after close | stale generation excluded | close/admission contracts checked | flow export parity reviewed | callbacks bounded and batched | direct exporter contracts refuted candidate |
| `pkg/daemon/daemon_flowexport_flowdir_test.go` | flow export | negative | ingress/egress direction metadata reaches collectors correctly | correctness checked | no leak | parity relevant | test-only | regression present |
| `pkg/daemon/daemon_flowexport_reconcile_test.go` | flow export | negative | collector additions/removals replace and close the exact generation | stale collector teardown checked | concurrent close paths covered | parity relevant | bounded collectors | comprehensive lifecycle tests |
| `pkg/daemon/daemon_flowexport_session_close_test.go` | flow export | negative | session-close callbacks cannot strand records in retired batches | admission fence checked | close race covered | parity relevant | batch path bounded | race regression present |
| `pkg/daemon/daemon_flowtrace_3932_test.go` | flow tracing | negative | one stable callback targets only the active writer | disabled state is no-op | atomic pointer lifecycle checked | parity relevant | event dispatch remains O(1) | regression present |
| `pkg/daemon/daemon_forwarding_status.go` | telemetry/status | negative | unavailable dataplane returns honest empty/unavailable status | no false healthy state | nil-safe, no leak | userspace runtime only | status calls bounded | probe interfaces narrow |
| `pkg/daemon/daemon_forwarding_status_test.go` | telemetry/status | negative | forwarding and drop metrics preserve runtime truth | negative states checked | no race gap | userspace runtime only | test-only | coverage present |
| `pkg/daemon/daemon_gc.go` | session GC | negative | GC tuning updates only a live collector | nil path safe | no new lifecycle | userspace runtime only | hot-path settings not recomputed per packet | minimal wrapper adequate |
| `pkg/daemon/daemon_gc_test.go` | session GC | negative | config toggles session-limit accounting correctly | correctness checked | no leak | userspace runtime only | test-only | regression present |
| `pkg/daemon/daemon_goroutine_shutdown_5308_test.go` | daemon shutdown | A7-b1-F004 | every daemonCtx-bound loop must be cancelled and joined before dependencies | two known loops covered | aggregator/IPsec retry are omitted | N/A | shutdown-only | test scope itself exposes the missing inventory |

### HA, userspace synchronization, and VIP ownership

| Path | Module/subsystem | Result | Invariant checked | C/S/F | M/C/L | vSRX | Perf | Mod/tests |
|---|---|---|---|---|---|---|---|---|
| `pkg/daemon/daemon_ha.go` | HA state/service orchestration | A7-b1-F001 | RG ownership, RA, DHCP, routes, and names must share one kernel-interface identity | tagged RETH DHCP/RA names diverge | state locks/timers reviewed | cluster RETH parity affected | transition work bounded by RG/interface count | name derivation duplicated across helpers |
| `pkg/daemon/daemon_ha_fabric.go` | HA fabric | negative | overlay creation, neighbor refresh, and monitor resync preserve peer reachability | netlink failures logged/returned at authority boundaries | ticker/subscription contexts checked | HA fabric parity relevant | event-driven; bounded refresh cadence | duplicated v4/v6 paths noted but no finding |
| `pkg/daemon/daemon_ha_fabric_test.go` | HA fabric | negative | overlay/address/neighbor states reconcile deterministically | failure matrix checked | channel lifecycle tested | HA parity relevant | test-only | coverage present |
| `pkg/daemon/daemon_ha_fence_3917_test.go` | HA fencing | negative | losing ownership fences forwarding before service teardown | fail-closed order checked | transition synchronization covered | HA parity critical | control path | regression present |
| `pkg/daemon/daemon_ha_sync.go` | HA comms/config/session sync | negative | one cluster generation owns heartbeat, listeners, and synced state | stale generations fenced | local comms context and joins checked | HA parity relevant | bounded channels/tickers | large module, but generation contract is explicit |
| `pkg/daemon/daemon_ha_sync_test.go` | HA comms/config/session sync | negative | sync start/stop/restart and failure paths preserve state | negative cases checked | cancellation/join paths exercised | HA parity relevant | test-only | broad coverage present |
| `pkg/daemon/daemon_ha_userspace.go` | userspace HA adapter | negative | daemon state maps exactly to userspace runtime controls | fail-closed mapping checked | no ownership issue | sole runtime path | control socket only | thin adapter |
| `pkg/daemon/daemon_ha_userspace_convert.go` | userspace HA conversion | negative | session/NAT/wire fields preserve widths, address family, and semantics | truncation/endian conversions reviewed | copies own backing data | userspace parity | batch conversion only | conversion helpers focused |
| `pkg/daemon/daemon_ha_userspace_export.go` | userspace HA export | negative | exported sessions preserve immutable snapshot semantics | malformed entries skipped visibly | bounded copies | userspace parity | batch path | narrow adapter |
| `pkg/daemon/daemon_ha_userspace_readiness.go` | userspace HA readiness | negative | promotion waits for required runtime/config readiness | fail-closed readiness checked | atomic state checked | HA parity relevant | no high-frequency polling | explicit readiness helper |
| `pkg/daemon/daemon_ha_userspace_stream.go` | userspace HA event stream | negative | reconnect/backoff and event application preserve generation ordering | stream errors do not assert readiness | context/ticker ownership checked | sole runtime path | bounded backoff/batches | stream state machine clear |
| `pkg/daemon/daemon_ha_vip.go` | direct VIP ownership | negative | only active RG owns VIPs and stable link-locals use VLAN ID | fail-closed ownership checked | announce cancellation guarded | HA parity relevant | transition-only | this file demonstrates correct unit-to-VLAN mapping |
| `pkg/daemon/daemon_health.go` | daemon health | negative | asynchronous health snapshots reflect current config/runtime state | no false success found | goroutine is short-lived per check | parity observability reviewed | low-frequency | helper seams adequate |

### IP monitoring, IPsec, neighbor, host policy, RA, RETH, and RPM

| Path | Module/subsystem | Result | Invariant checked | C/S/F | M/C/L | vSRX | Perf | Mod/tests |
|---|---|---|---|---|---|---|---|---|
| `pkg/daemon/daemon_ipmon.go` | IP monitoring/FRR overlay | negative | probe winners publish reversible route overlays and honor HA ownership | fail/degraded paths checked | callbacks/state synchronized | parity relevant | probe cadence bounded | FRR writer centralized |
| `pkg/daemon/daemon_ipmon_test.go` | IP monitoring/FRR overlay | negative | next-hop, overlay, and gate transitions converge | negative cases checked | race-sensitive callbacks tested | parity relevant | test-only | broad coverage present |
| `pkg/daemon/daemon_ipsec_apply_test.go` | IPsec apply | negative | IPsec apply errors reach commit result and stale tunnels are not reported converged | fail-closed result checked | no lifecycle assertion | parity relevant | apply-only | error regression present |
| `pkg/daemon/daemon_ipsec_rebind.go` | DHCP-bound IPsec rebind | A7-b1-F004 | retry loop must stop and join with daemon lifetime | retry convergence correct | production daemonCtx never cancels this loop | parity relevant | 30s control-plane cadence | lacks stop helper/WaitGroup |
| `pkg/daemon/daemon_ipsec_rebind_4899_test.go` | DHCP-bound IPsec rebind | A7-b1-F004 | failed rebind raises health and retries until success or shutdown | retry/health covered | fixture supplies its own cancellable context | parity relevant | accelerated test cadence | production shutdown gap untested |
| `pkg/daemon/daemon_linkstate_monitor_3950_test.go` | netlink link monitor | negative | ENOBUFS/subscription errors trigger full catch-up without stale link state | resync checked | listener lifetime covered | operational parity | bounded channel and inventory scan | regression present |
| `pkg/daemon/daemon_lldp_reconcile_test.go` | LLDP lifecycle | negative | enable/change/delete starts exactly one manager and stops stale state | teardown checked | manager lifecycle covered | parity relevant | low-frequency | regression present |
| `pkg/daemon/daemon_login_optinjection_5005_test.go` | login host integration | negative | generated account tooling cannot interpret configured values as options | argv injection blocked | no leak | login parity relevant | apply-only | adversarial regression present |
| `pkg/daemon/daemon_natpoolalarm.go` | NAT pool alarm | negative | one monitor generation reports current dataplane utilization | nil/degraded states honest | atomic pointer and stop path checked | parity relevant | periodic control query | lifecycle helper focused |
| `pkg/daemon/daemon_natpoolalarm_race_test.go` | NAT pool alarm | negative | concurrent apply/status/stop cannot race stale monitor state | correctness checked | race regression present | parity relevant | test-only | coverage adequate |
| `pkg/daemon/daemon_neighbor.go` | proactive neighbor resolution | A7-b1-F001 | interface-bound next hops must resolve the actual VLAN netdev | logical-unit suffix can target nonexistent netdev | goroutine fanout bounded by targets | tagged RETH parity affected | periodic scans bounded by config | uses noncanonical resolver |
| `pkg/daemon/daemon_neighbor_listener.go` | neighbor event listener | negative | netlink loss/debounce and failed-neighbor cleanup converge state | errors trigger resync | timers/channels/context checked | operational parity | debounced and bounded | listener split is coherent |
| `pkg/daemon/daemon_neighbor_listener_test.go` | neighbor event listener | negative | event burst, overflow, and shutdown behavior preserve updates | negative cases checked | race/lifetime covered | operational parity | test-only | regression present |
| `pkg/daemon/daemon_networkd_apply_test.go` | networkd integration | negative | empty desired state still sweeps stale generated files | stale state teardown checked | no leak | host integration parity | commit-only | manager activation debt tested elsewhere, not device-map bypass |
| `pkg/daemon/daemon_nft.go` | host nftables | negative | host-input/lo0 rules render atomically and fail commit on enforcement errors | fail-closed command path checked; known addressless issue suppressed | command timeout bounded | host-inbound parity reviewed | apply-only | renderer is centralized |
| `pkg/daemon/daemon_policy_default_4342_test.go` | session invalidation | negative | default-policy changes clear affected live sessions | stale authorization checked | synchronized apply path | parity relevant | commit-only | regression present |
| `pkg/daemon/daemon_policy_invalidate.go` | session invalidation | negative | deleted/modified/default policies invalidate the exact runtime sessions | over/under-clear paths reviewed | bounded snapshots; no race found | parity relevant | commit-time control socket work | helper separation clear |
| `pkg/daemon/daemon_policy_invalidate_test.go` | session invalidation | negative | policy diffs map to exact clear requests | correctness matrix checked | no leak | parity relevant | test-only | broad coverage present |
| `pkg/daemon/daemon_policy_modified_4234_test.go` | session invalidation | negative | policy-ID zero and content modifications cannot retain stale authorization | known ID-zero cases covered/suppressed | no race | parity relevant | test-only | regression present |
| `pkg/daemon/daemon_policy_scheduler_4343_test.go` | policy scheduler | negative | scheduler republish handles sentinel/default IDs without aliasing policy zero | fail-closed state checked | scheduler lifecycle covered separately | parity relevant | periodic updates bounded | regression present |
| `pkg/daemon/daemon_proxyarp.go` | proxy ARP/NDP | negative | desired entries reconcile to actual VLAN/RETH ifindexes and stale state is removed | malformed/unresolved entries do not broaden | periodic reassert context checked | parity relevant | interval-based, bounded maps | canonical resolver used here |
| `pkg/daemon/daemon_proxyarp_orphan_4955_test.go` | proxy ARP/NDP | negative | orphaned kernel state is removed after config deletion | teardown checked | no leak | parity relevant | test-only | regression present |
| `pkg/daemon/daemon_proxyarp_test.go` | proxy ARP/NDP | A7-b1-F001 | kernel VLAN netdev suffix is VLAN ID, not logical unit | contract explicitly proven | no lifecycle issue | tagged-unit parity relevant | test-only | exposes missing cross-module SSOT |
| `pkg/daemon/daemon_ra.go` | router advertisement | A7-b1-F001 | RA sender must bind the real kernel interface for a configured logical unit | tagged RETH sender name is wrong | cloned configs avoid mutation races | IPv6/RETH parity affected | reconcile-only | should call canonical kernel-name resolver |
| `pkg/daemon/daemon_reth.go` | RETH link/MAC/link-local | A7-b1-F001 | unit-map key and VLAN ID must remain distinct through link-local recovery | helper is indexed by unit but caller passes VLAN ID | netlink operations serialized by apply | RETH parity affected | transition-only | misleading comment and missing mismatch test |
| `pkg/daemon/daemon_reth_rename_up_test.go` | RETH rename/MAC | negative | rename/MAC paths restore link UP on success and failure | availability checked | no leak | RETH parity relevant | test-only | regression present |
| `pkg/daemon/daemon_rpm.go` | RPM probes/routing pins | negative | probe generations and pin retry state converge on config changes | stale pins/probes checked | dedicated cancel/join exists | parity relevant | bounded cadence | lifecycle SSOT is explicit |
| `pkg/daemon/daemon_rpm_test.go` | RPM probes/routing pins | negative | add/change/delete and result publication preserve probe state | negative transitions checked | cancellation tested | parity relevant | test-only | broad coverage present |

### Run/shutdown, scheduler, SNMP, SSH/system integration, device map, and direct HA

| Path | Module/subsystem | Result | Invariant checked | C/S/F | M/C/L | vSRX | Perf | Mod/tests |
|---|---|---|---|---|---|---|---|---|
| `pkg/daemon/daemon_run.go` | daemon run/shutdown | A7-b1-F004 | all feature goroutines must stop before dependent managers/runtime | shutdown order otherwise fail-closed | only policy scheduler and pin retry get explicit daemonCtx stop/join | N/A | shutdown-only | no complete loop ownership inventory |
| `pkg/daemon/daemon_run_test.go` | daemon run/shutdown | negative | startup helpers and shutdown updates honor context/error contracts | negative paths checked | selected lifecycle helpers tested | HA/runtime parity relevant | test-only | does not exercise F004 loops |
| `pkg/daemon/daemon_scheduler.go` | policy scheduler | negative | config changes replace scheduler atomically and shutdown prevents restart | stale schedule state excluded | dedicated cancel/WaitGroup checked | parity relevant | minute-scale control work | lifecycle helper + tests align |
| `pkg/daemon/daemon_scheduler_republish_3780_test.go` | policy scheduler | negative | restart republishes current schedule state | correctness checked | no leak | parity relevant | test-only | regression present |
| `pkg/daemon/daemon_scheduler_test.go` | policy scheduler | negative | start/replace/stop and callback apply serialization hold | fail paths checked | cancellation/join covered | parity relevant | test-only | broad coverage present |
| `pkg/daemon/daemon_snmp_hash_clients_5105_test.go` | SNMP reconcile | negative | semantically identical client/source sets do not churn the agent | stable hash checked | no leak | SNMP parity relevant | avoids needless restarts | regression present |
| `pkg/daemon/daemon_snmp_reconcile.go` | SNMP lifecycle | negative | desired SNMP config, link trap monitor, and clients share one owned generation | stale agent teardown checked | dedicated cancel/join present | parity relevant | link snapshots bounded | lifecycle centralized |
| `pkg/daemon/daemon_snmp_reconcile_test.go` | SNMP lifecycle | negative | enable/change/delete and link-state updates converge agent state | negative cases checked | shutdown coverage present | parity relevant | test-only | broad coverage present |
| `pkg/daemon/daemon_ssh_test.go` | SSH daemon config | A7-b1-F005 | every managed SSH artifact must revoke removed config | sshd drop-in teardown covered; global known-host file is not | no persistent worker | SSH parity affected | apply-only | no `ssh_known_hosts` transition test |
| `pkg/daemon/daemon_sudoers_reconcile_3889_test.go` | login/sudoers | negative | class downgrade/removal revokes stale grants | privilege revocation checked | no leak | login parity relevant | apply-only | regression present |
| `pkg/daemon/daemon_sudoers_username_4895_test.go` | login/sudoers | negative | usernames cannot escape managed sudoers filenames/content | injection checked | no leak | login parity relevant | apply-only | adversarial regression present |
| `pkg/daemon/daemon_system.go` | host config/session reporting | A7-b1-F004, A7-b1-F005 | generated host files and reporting workers must reconcile both creation and deletion | known-host revocation missing | aggregator context is not shutdown-owned | SSH/report parity affected | cold apply; callback O(1) | two lifecycle transitions lack tests |
| `pkg/daemon/dataplane_boot_test.go` | dataplane boot | negative | boot starts only the userspace runtime with correct readiness/error behavior | no legacy fail-open path found | startup/close seams checked | sole runtime path | boot-only | regression present |
| `pkg/daemon/deferred_mac_reapply_5134_test.go` | RETH MAC/apply | negative | deferred MAC work re-runs only after required links/runtime exist | stale deferred state checked | serialized apply | RETH parity relevant | transition-only | regression present |
| `pkg/daemon/device_map.go` | bare-metal device map | A7-b1-F002, A7-b1-F003 | management preflight must fail closed and activation failures must retain retry debt | enumeration error bypasses gate; reload debt lost | no memory issue; state transition is nontransactional | bare-metal parity relevant | boot/commit inventory scans | direct reload bypasses manager SSOT |
| `pkg/daemon/device_map_rename_err_4956_test.go` | bare-metal device map | negative | startup rename/reload errors preserve the naming retry marker | errors surfaced | no leak | bare-metal parity relevant | test-only | startup path covered, teardown path distinct |
| `pkg/daemon/device_map_startup_test.go` | bare-metal device map | A7-b1-F002 | boot chooses mapped naming whenever committed device-map is active | proves startup applies without re-running commit preflight | no leak | bare-metal parity relevant | boot-only | no unsafe-map startup rejection test |
| `pkg/daemon/device_map_teardown_failclosed_5309_test.go` | bare-metal device map | A7-b1-F003 | failed teardown must keep durable state until activation succeeds | reload test checks only error, not retained debt | no leak | bare-metal parity relevant | test-only | test name/comment overstate reload retention |
| `pkg/daemon/device_map_test.go` | bare-metal device map | A7-b1-F002 | strand detector catches management rename/collision scenarios | detector is sound when inventory exists | no leak | bare-metal parity relevant | test-only | no enumeration-error preflight case |
| `pkg/daemon/dhcp_nexthop_resolver_test.go` | DHCP naming/next-hop | A7-b1-F001 | DHCP lease keys use VLAN ID when unit number differs | canonical contract proven | no leak | tagged-unit parity relevant | test-only | does not cover RETH service resolver |
| `pkg/daemon/dhcp_recompile_test.go` | DHCP apply | negative | management-only lease changes avoid unnecessary dataplane compile | correctness checked | no leak | parity relevant | avoids expensive recompiles | regression present |
| `pkg/daemon/dhcp_reconcile_test.go` | DHCP client lifecycle | negative | DHCP clients key tagged units by VLAN ID and stop on deletion | correct client naming checked | manager start/stop covered | parity relevant | config-change only | unit/VLAN contract present for clients |
| `pkg/daemon/direct_announce_test.go` | direct HA announcements | negative | repeated announcements stop immediately on cancellation/ownership loss | stale owner suppression checked | timers generation-fenced | HA parity relevant | bounded burst schedule | regression present |
| `pkg/daemon/direct_garp_gate_test.go` | direct HA announcements | negative | abdication stops remaining GARP/NA follow-ups | fail-closed ownership gate checked | concurrent sequence/ownership guarded | HA parity relevant | bounded burst | adversarial regression present |
| `pkg/daemon/direct_garp_probe_target_test.go` | direct HA ARP probe | negative | gateway probe target remains inside prefix and sender is VIP | address arithmetic checked | no leak | HA parity relevant | transition-only | prefix edge cases covered |
| `pkg/daemon/direct_vip_ownership_test.go` | direct HA VIPs | negative | stale VIPs are removed even without an ownership edge | fail-closed removal checked | state synchronization checked | HA parity relevant | transition-only | regression present |
| `pkg/daemon/exec_timeout.go` | external commands | negative | host commands have a hard timeout and process-context cancellation | timeout errors preserved | context cancellation bounds process lifetime | N/A | cold path | small shared helper |
| `pkg/daemon/failover_commit_ready_test.go` | HA failover readiness | negative | promotion waits for local apply settle and rejects stale epochs with changed intent | readiness fails closed on timeout | epoch synchronization checked | HA parity relevant | bounded wait | transition coverage present |

### A7-b2: Daemon lifecycle and Linux host integration (119 files)

Batch-list SHA-256: `a27e56d00021dc49b1c72e32b33e41383533eb965f76411ca7a279a61e143852`.

### Daemon lifecycle and host integration

- **Correctness/security/fail-open:** Traced boot/apply/rollback, HA state transitions, host login revocation, host filtering, IPsec lease rebind, management VRF, syslog, DNS, NTP, and tunnel readiness. Findings A7-b2-F001 and A7-b2-F002 are fail-open/stale-state defects; all other reviewed paths had concrete negative results.
- **Memory safety/concurrency/truncation/leaks:** Reviewed apply serialization, mutex-protected RG state, retry contexts, goroutine cancellation, subprocess timeouts, atomic generated-state writes, netlink error handling, and numeric narrowing. `go test -race` passed; no additional race, leak, panic, or truncation finding survived.
- **vSRX completeness:** Compared Junos-style host-inbound, per-RG, lo0, static-next-hop, login, syslog, NTP, and HA semantics represented in this slice. No standalone parity gap survived; findings are implementation defects rather than missing feature claims.
- **Performance/latency:** Reviewed periodic loops, neighbor reconciliation, userspace synchronization, runtime probes, and RSS programming. A7-b2-F003 can strand RSS on one worker; no new packet-path allocation, lock-contention, unbounded-scan, or helper-socket-frequency finding survived.
- **Modularity/test gaps:** Direct contracts were followed only where needed. Existing tests are broad, but login tests do not distinguish passwd I/O failure from account absence, HA tests manually trigger the reconcile omitted by production, and RSS tests accept range-only tables; these gaps map to F001-F003.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/daemon/frr_failclosed_boot_test.go` | daemon/FRR boot | negative | Compile/render failure cannot promote partial FRR state. |
| `pkg/daemon/frr_fullconfig_guard_test.go` | daemon/FRR apply | negative | FullConfig guards reject nil or partial routing input without stale promotion. |
| `pkg/daemon/hb165_bootstrap_batch_test.go` | daemon/bootstrap | negative | Bootstrap batches preserve apply ordering and error visibility. |
| `pkg/daemon/heartbeat_retry_ctx_test.go` | daemon/HA heartbeat | negative | Retry goroutines terminate with their communication context. |
| `pkg/daemon/host_inbound_addressless_3698_test.go` | daemon/host firewall | negative | Addressless interfaces do not broaden host-inbound acceptance. |
| `pkg/daemon/host_inbound_ambiguous_3718_test.go` | daemon/host firewall | negative | Ambiguous interface ownership fails closed. |
| `pkg/daemon/host_inbound_icmp_degenerate_4813_test.go` | daemon/host firewall | negative | Degenerate ICMP selectors do not become wildcard accepts. |
| `pkg/daemon/host_inbound_junos_host_4146_test.go` | daemon/host firewall | negative | Junos host/system-service semantics remain distinct. |
| `pkg/daemon/host_inbound_nft_test.go` | daemon/host firewall | negative | nftables rendering preserves service and interface scoping. |
| `pkg/daemon/host_inbound_parity_test.go` | daemon/host firewall | negative | Host-inbound policy remains consistent across render paths. |
| `pkg/daemon/host_inbound_per_iface_3362_test.go` | daemon/host firewall | negative | Per-interface rules do not leak to sibling interfaces. |
| `pkg/daemon/host_inbound_ssot_render_3627_test.go` | daemon/host firewall | negative | One compiled policy is the source of truth for rendering. |
| `pkg/daemon/host_inbound_unzoned_4420_test.go` | daemon/host firewall | negative | Unzoned interfaces do not inherit zoned permits. |
| `pkg/daemon/host_tunables.go` | daemon/sysctl | negative | Tunable writes are bounded, validated, and reversible. |
| `pkg/daemon/host_tunables_daemon.go` | daemon/sysctl lifecycle | negative | Daemon setup/restore paths retain errors and ownership. |
| `pkg/daemon/host_tunables_restore_applysem_4691_test.go` | daemon/sysctl lifecycle | negative | Restore is serialized against apply. |
| `pkg/daemon/host_tunables_restore_test.go` | daemon/sysctl lifecycle | negative | Original host values are restored without fabricated defaults. |
| `pkg/daemon/host_tunables_test.go` | daemon/sysctl | negative | Parsing, writes, and failure handling remain scoped. |
| `pkg/daemon/interface_addr_test.go` | daemon/netlink address | negative | Address reconciliation preserves family and ownership boundaries. |
| `pkg/daemon/ipsec_lease_rebind_test.go` | daemon/IPsec rebind | negative | DHCP lease changes are translated to bounded IPsec rebind work. |
| `pkg/daemon/ipsec_sa_sync_empty_4385_test.go` | daemon/IPsec HA | negative | Empty SA synchronization clears rather than preserves peer state. |
| `pkg/daemon/ipv6_static_nexthop_test.go` | daemon/routing | negative | IPv6 next-hop interface resolution remains family-correct. |
| `pkg/daemon/kernel_selfrecover.go` | daemon/self-recovery | negative | Recovery state parsing and action gates do not widen on partial input. |
| `pkg/daemon/legacy_dataplane_canary_synthetic_test.go` | daemon/dataplane retirement | negative | Synthetic legacy signals do not re-enable retired forwarding. |
| `pkg/daemon/legacy_dataplane_canary_test.go` | daemon/dataplane retirement | negative | Runtime canary enforces userspace-only forwarding. |
| `pkg/daemon/linksetup.go` | daemon/link setup | negative | Link discovery, rename, queue, and userspace binding errors stay scoped. |
| `pkg/daemon/linksetup_collision_4178_test.go` | daemon/link rename | negative | Rename collisions fail without taking unrelated links. |
| `pkg/daemon/linksetup_rename_test.go` | daemon/link rename | negative | Rename sequencing preserves identity and idempotence. |
| `pkg/daemon/lo0_filter_test.go` | daemon/host firewall | negative | lo0 filters do not leak to transit or physical interfaces. |
| `pkg/daemon/login_deprovision_5128_test.go` | daemon/login teardown | A7-b2-F001 | Removed credentials are revoked, including failure/retry paths. |
| `pkg/daemon/login_emptied_keys_5106_test.go` | daemon/login keys | negative | Empty configured key sets remove managed key material. |
| `pkg/daemon/login_password.go` | daemon/login lifecycle | A7-b2-F001 | Account absence must be distinguished from passwd database failure. |
| `pkg/daemon/login_password_functional_test.go` | daemon/login lifecycle | negative | Password mutation commands and shadow checks are scoped. |
| `pkg/daemon/login_password_test.go` | daemon/login lifecycle | negative | Marker, UID/GID, and password helpers handle ordinary inputs. |
| `pkg/daemon/mgmtvrf_race_test.go` | daemon/management VRF | negative | Concurrent reads do not race VRF interface publication. |
| `pkg/daemon/mgmtvrf_route_reconcile_5108_test.go` | daemon/management VRF | negative | Route reconciliation removes stale entries and surfaces failures. |
| `pkg/daemon/neighbor_periodic_guard_test.go` | daemon/neighbors | negative | Periodic neighbor work is lifecycle-gated and bounded. |
| `pkg/daemon/nft_chain_priority_test.go` | daemon/nftables | negative | Chain priority ordering preserves policy precedence. |
| `pkg/daemon/ntp_test.go` | daemon/NTP | negative | NTP render and teardown retain service and input boundaries. |
| `pkg/daemon/per_rg_test.go` | daemon/HA per-RG | negative | Per-RG ownership and dataplane updates remain isolated. |
| `pkg/daemon/per_rg_zoneid_3704_test.go` | daemon/HA per-RG | negative | Zone IDs remain symmetric and RG-scoped. |
| `pkg/daemon/persistent_snat_apply_test.go` | daemon/NAT apply | negative | Persistent SNAT apply does not partially promote failed state. |
| `pkg/daemon/policy_scheduler_apply_test.go` | daemon/policy scheduler | negative | Scheduler publication follows committed policy state. |
| `pkg/daemon/ra_source_test.go` | daemon/router advertisements | negative | RA source selection is interface- and family-scoped. |
| `pkg/daemon/resolve_neighbor_test.go` | daemon/neighbors | negative | Neighbor resolution rejects malformed and ambiguous targets. |
| `pkg/daemon/rg_state.go` | daemon/HA state machine | A7-b2-F002 | Ownership mode changes must atomically reconcile `rg_active`. |
| `pkg/daemon/rg_state_test.go` | daemon/HA state machine | A7-b2-F002 | Mode toggles must not require an unrelated later event. |
| `pkg/daemon/rollback_resync_test.go` | daemon/rollback | negative | Rollback republishes every dependent subsystem. |
| `pkg/daemon/rollback_serialize_test.go` | daemon/rollback | negative | Rollback and commit cannot interleave apply state. |
| `pkg/daemon/root_auth_revoke_5276_test.go` | daemon/root auth | negative | Root credential removal revokes both password and managed keys. |
| `pkg/daemon/rss_indirection.go` | daemon/RSS | A7-b2-F003 | Idempotence requires the intended distribution, not only in-range queue IDs. |
| `pkg/daemon/rss_indirection_test.go` | daemon/RSS | A7-b2-F003 | Degenerate but in-range RSS tables must be rejected. |
| `pkg/daemon/runtime_probes.go` | daemon/runtime probes | negative | Probe subprocesses are time-bounded and parse failures stay unknown. |
| `pkg/daemon/runtime_probes_test.go` | daemon/runtime probes | negative | Probe error and malformed-output cases do not report false health. |
| `pkg/daemon/session_sync_readiness_test.go` | daemon/HA sessions | negative | Session synchronization waits for the required readiness fence. |
| `pkg/daemon/syslog_close_3579_test.go` | daemon/syslog | negative | Removed clients close and cease delivery. |
| `pkg/daemon/syslog_reconcile_5111_test.go` | daemon/syslog | negative | Destination reconciliation tears down stale clients. |
| `pkg/daemon/syslog_severity_5314_test.go` | daemon/syslog | negative | Severity mapping does not broaden emitted classes. |
| `pkg/daemon/syslog_source_test.go` | daemon/syslog | negative | Source-address binding remains explicit and family-correct. |
| `pkg/daemon/syslog_teardown_3351_test.go` | daemon/syslog | negative | Teardown is terminal and idempotent. |
| `pkg/daemon/system/dns.go` | daemon/DNS | negative | Resolver rendering validates and atomically replaces generated state. |
| `pkg/daemon/system/dns_test.go` | daemon/DNS | negative | Nameserver/search rendering handles empty and invalid input safely. |
| `pkg/daemon/system_dns_nameserver_belt_5010_test.go` | daemon/DNS | negative | Render-time belt blocks nameserver directive injection. |
| `pkg/daemon/system_string_injection_belt_4902_test.go` | daemon/system render | negative | Control characters cannot create service directives. |
| `pkg/daemon/time_zone_symlink_belt_5011_test.go` | daemon/time zone | negative | Time-zone paths cannot escape the zoneinfo tree. |
| `pkg/daemon/tunnel_anchor_test.go` | daemon/tunnels | negative | Tunnel anchoring preserves route/interface lifecycle ordering. |
| `pkg/daemon/userspace_sync_test.go` | daemon/userspace publication | negative | Userspace synchronization does not publish partial config. |
| `pkg/daemon/vip_readiness_test.go` | daemon/HA VIP | negative | VIP ownership is readiness-fenced before forwarding. |
| `pkg/daemon/web_management_clamp_4047_test.go` | daemon/web management | negative | Management listeners remain loopback-clamped. |
| `pkg/daemon/zoneid_ha_symmetry_test.go` | daemon/HA zones | negative | Zone identity is deterministic across peers. |

### FRR rendering and operations

- **Correctness/security/fail-open:** Traced managed-section writes, reloads, static routes, BGP neighbors, policies, route maps, status parsers, and vtysh execution. F004 leaves malformed BGP peers in later stanzas; F005 suppresses DHCP fallback for a static default that renders nothing; F007 masks all route-detail failures.
- **Memory safety/concurrency/truncation/leaks:** Reviewed manager locking, executor seams, scanner/JSON parsing, atomic writes, command timeouts, integer formatting, and partial output. No memory-safety, race, descriptor, truncation, or process-lifecycle finding survived.
- **vSRX completeness:** Checked Junos BGP, policy, static/floating/ECMP, forwarding-instance and route-detail semantics represented here. No separate parity gap survived; the findings are concrete divergences in already-claimed behavior.
- **Performance/latency:** Rendering sorts bounded configuration collections and status work is operator-triggered. No packet-path or high-frequency helper-socket finding survived.
- **Modularity/test gaps:** Neighbor validity is duplicated across declaration, AF, and BFD loops instead of using one filtered set; default-route presence is duplicated from static-route renderability; status errors are discarded below callers that already handle errors. Existing tests cover each local happy path but miss these compositions.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/frr/bgp_neighbor_ip_guard_4588_test.go` | FRR/BGP show | negative | Neighbor addresses are validated before command construction. |
| `pkg/frr/bgp_remote_as_2963_test.go` | FRR/BGP render | A7-b2-F004 | A peer with AS 0 is absent from every generated stanza. |
| `pkg/frr/bgp_summary_3942_test.go` | FRR/BGP status | negative | Summary parser handles FRR JSON shapes without false peers. |
| `pkg/frr/config_render.go` | FRR/static and DHCP routes | A7-b2-F005 | DHCP suppression depends on an effective static default. |
| `pkg/frr/executor_test.go` | FRR/executor | negative | Command seams preserve arguments, output, and errors. |
| `pkg/frr/fbf_table_render_test.go` | FRR/FBF | negative | Forwarding-instance table IDs stay attached to intended routes. |
| `pkg/frr/frr_clusterid_origin_render_4919_test.go` | FRR/BGP policy | negative | Cluster-ID and origin rendering remain syntactically scoped. |
| `pkg/frr/frr_test.go` | FRR/integration render | negative | Broad protocol/static/managed-section rendering contracts hold. |
| `pkg/frr/frrconf_mode_4484_test.go` | FRR/config file | negative | Managed config permissions are repaired without widening access. |
| `pkg/frr/manager.go` | FRR/manager | negative | Apply writes and reload errors do not silently promote state. |
| `pkg/frr/manager_reload_test.go` | FRR/reload | negative | Reload command failures propagate. |
| `pkg/frr/policy_as_path_prepend_2892_test.go` | FRR/policy | negative | AS-path prepend output retains order and validation. |
| `pkg/frr/policy_default_action_2998_test.go` | FRR/policy | negative | Default policy action maps to explicit terminal behavior. |
| `pkg/frr/policy_injection_4097_test.go` | FRR/policy | negative | Policy names and values cannot inject FRR directives. |
| `pkg/frr/policy_redist_alias_collision_5116_test.go` | FRR/policy | negative | Redistribution aliases cannot collide into unrelated route maps. |
| `pkg/frr/policy_render.go` | FRR/BGP and policy render | A7-b2-F004 | One validity decision must govern all neighbor stanzas. |
| `pkg/frr/policy_routemap_leak_4481_test.go` | FRR/policy | negative | Missing route maps do not become permit-all policy. |
| `pkg/frr/policy_setclause_injection_4482_test.go` | FRR/policy | negative | Set-clause values cannot escape their directive. |
| `pkg/frr/preferred_routes_test.go` | FRR/static routes | negative | Preference and selected route rendering remain deterministic. |
| `pkg/frr/router_id_2980_test.go` | FRR/BGP/OSPF | negative | Invalid router IDs do not poison generated protocol config. |
| `pkg/frr/routing_adjacency_4285_test.go` | FRR/adjacency | negative | Adjacency output remains interface and protocol scoped. |
| `pkg/frr/static_ecmp_list_3872_test.go` | FRR/static routes | negative | ECMP list members render independently and deterministically. |
| `pkg/frr/static_empty_route_3872_test.go` | FRR/static routes | A7-b2-F005 | An empty static route renders nothing without suppressing fallback. |
| `pkg/frr/static_floating_3871_test.go` | FRR/static routes | negative | Qualified next-hop preferences remain per next hop. |
| `pkg/frr/status_parse.go` | FRR/route status | A7-b2-F007 | Operational query/parse failures must reach callers. |
| `pkg/frr/testseam.go` | FRR/test seam | negative | Executor substitution is scoped and production defaults remain intact. |
| `pkg/frr/vtysh.go` | FRR/vtysh | negative | Command execution is time-bounded and output/error preserving. |

### IPsec rendering and lifecycle

- **Correctness/security/fail-open:** Traced proposal construction, gateway/policy resolution, swanctl rendering, reload ordering, applied-name promotion, SA enumeration, deletion, DHCP rebind, and error paths. F006 is a deliberate fail-open path where an omitted connection retains live SAs; all other candidates were negative.
- **Memory safety/concurrency/truncation/leaks:** Reviewed manager mutex use, command timeouts, string builders, deterministic child-name hashing, integer conversions, and reload state ordering. No race, panic, descriptor, goroutine, or truncation finding survived; race tests passed.
- **vSRX completeness:** Checked IKE/IPsec proposal, DH group, selector, gateway-family, link-local, AH rejection, and multi-value behavior represented in this slice. No independent parity-only gap survived.
- **Performance/latency:** Work occurs on config apply, lease rebind, or explicit status/teardown, not per packet. No hot-path or unbounded control-socket finding survived.
- **Modularity/test gaps:** Rendering knows which VPNs were skipped, but manager lifecycle tracking reconstructs names from the unfiltered input and loses that fact. Tests cover skip rendering and deleted-SA teardown separately, not the transition between them; this maps to F006.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/ipsec/childname_collision_5122_test.go` | IPsec/child naming | negative | Sanitized child names remain collision-resistant and deterministic. |
| `pkg/ipsec/crypto.go` | IPsec/crypto render | negative | Algorithm and DH mappings do not silently fabricate supported suites. |
| `pkg/ipsec/delete_terminate_3941_test.go` | IPsec/SA teardown | negative | Explicitly deleted VPNs terminate established SAs. |
| `pkg/ipsec/dhcp_rebind_test.go` | IPsec/DHCP rebind | negative | Address rebind updates are family-scoped and reload errors surface. |
| `pkg/ipsec/dhgroup_roundtrip_test.go` | IPsec/crypto render | negative | DH group values round-trip to strongSwan tokens correctly. |
| `pkg/ipsec/ike.go` | IPsec/IKE resolution | negative | IKE chains and authentication settings fail closed when unresolved. |
| `pkg/ipsec/ike_chain_failclosed_test.go` | IPsec/IKE render belt | A7-b2-F006 | A skipped invalid VPN must not leave its prior SA forwarding. |
| `pkg/ipsec/ike_proposals_multivalue_3904_test.go` | IPsec/IKE proposals | negative | Multi-value proposals preserve every valid suite. |
| `pkg/ipsec/ipsec_test.go` | IPsec/core tests | negative | General rendering, parsing, and lifecycle behavior remains covered. |
| `pkg/ipsec/manager.go` | IPsec/manager | A7-b2-F006 | Applied connection tracking must reflect rendered connections. |
| `pkg/ipsec/manager_reload_ordering_4898_test.go` | IPsec/reload state | negative | Failed reloads do not advance applied-name state or tear down effective SAs. |
| `pkg/ipsec/matchfamily_linklocal_test.go` | IPsec/address families | negative | Link-local and mixed-family selectors do not cross families. |
| `pkg/ipsec/policy.go` | IPsec/swanctl render | A7-b2-F006 | Render-time skips must be carried into lifecycle teardown. |
| `pkg/ipsec/proposalset_ah_hb167_test.go` | IPsec/AH guard | negative | Unsupported AH cannot silently become ESP. |
| `pkg/ipsec/reload_error_4433_test.go` | IPsec/reload | negative | `swanctl --load-all` failures propagate. |
| `pkg/ipsec/swanctl_render_test.go` | IPsec/swanctl render | negative | Connection, child, secret, and selector syntax remains deterministic. |
| `pkg/ipsec/trafficselector_render_4098_test.go` | IPsec/selectors | negative | Traffic selectors are escaped, family-correct, and complete. |

### systemd-networkd integration

- **Correctness/security/fail-open:** Traced expected-file construction, atomic writes, protected management files, stale sweep, reload/reconfigure debt, `Clear`, rp_filter, and external ownership. The `Clear` reload-debt candidate was suppressed as the same root cause already tracked in `#4954`; no new finding survived.
- **Memory safety/concurrency/truncation/leaks:** Reviewed manager debt state, subprocess contexts, file iteration, error aggregation, and temporary-file behavior. No race, leak, panic, truncation, or partial-write finding survived.
- **vSRX completeness:** Checked address, DHCP-family, bond, bridge, VRF, rename, unmanaged, management protection, and teardown behavior represented here. No separate parity gap survived.
- **Performance/latency:** Reconciliation is commit-time and limits work to generated units/interfaces. No high-frequency or packet-path issue survived.
- **Modularity/test gaps:** Apply debt is tested, stale deletion is tested, and unit generation is decomposed. `Clear` lacks its own debt regression, but reporting it again would duplicate the tracked `#4954` root cause.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/networkd/networkd.go` | networkd/manager | negative | File reconciliation, protected ownership, and activation errors remain explicit. |
| `pkg/networkd/networkd_test.go` | networkd/unit render | negative | Link/network/netdev generation and empty-set sweeps remain scoped. |
| `pkg/networkd/reload_debt_4954_test.go` | networkd/activation debt | negative | Failed reload/reconfigure operations are retried on identical Apply. |
| `pkg/networkd/rpfilter_test.go` | networkd/rp_filter | negative | Global rp_filter hazards are detected without false certainty. |
| `pkg/networkd/stale_remove_4900_test.go` | networkd/stale teardown | negative | Remove failures fail Apply/Clear rather than reporting success. |

### A7-b3: Daemon lifecycle and Linux host integration (28 files)

Batch-list SHA-256: `f3a0759e5f3609840c683234251db5f8a972cd89a107c43d51652b782bd2cf0f`.

Every listed path was read from the detached worktree. The ledger records one
row for every assigned file. "Negative" means no additional finding survived
the source, call-chain, and duplicate review for that file.

### Bond lifecycle

Dimensions: correctness and transactional error propagation were traced through
the daemon apply caller; map mutation is serialized by `bondManager.mu`; this is
low-frequency control-plane netlink work with no packet-path cost; vSRX is not
applicable. The tests cover initial failures and no-churn but miss retry after a
partial member realization.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/routing/bond.go` | Fabric/AE bond reconcile | A7-b3-F001, A7-b3-F002 | A failed member operation must not be committed as a fully realized signature; only proven-not-found may release ownership. |
| `pkg/routing/bond_test.go` | Bond unit coverage | A7-b3-F001 | Covers initial LinkAdd/LinkSetMaster/bond-LinkSetUp errors, idempotence, and diffing; lacks failed-member retry and transient lookup cases. |

### Interface monitors

Dimensions: routing's snapshot is mutex-protected and copied, has no unsafe or
hot-packet work, and preserves vSRX peer-interface omission. A missing local
link candidate was refuted: the independent `pkg/cluster` periodic monitor is
the live HA demotion path and distinguishes peers by slot; this package supplies
bootstrap/display status only.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/routing/monitor.go` | HA interface status snapshot | Negative | Carrier state uses OperState rather than admin IFF_UP; returned status map is copied under lock. |
| `pkg/routing/monitor_test.go` | Monitor unit coverage | Negative | Covers OperDown, OperLowerLayerDown, OperUp, and OperUnknown fallback; no retained routing-only HA defect. |

### Probe pinning

Dimensions: marks/tables/priorities are bounded and deterministic, per-pin
errors prevent an unpinned probe from falsely passing, no shared mutable state
is retained, and the work is commit-time only. Dump failures are observable and
the tested rollback prevents partial pin installation; no candidate survived.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/routing/probe_pin.go` | RPM fwmark/table pin reconcile | Negative | Pin rules stay in the reserved band, use host routes with onlink/dev, and route-add failure rolls back the rule. |
| `pkg/routing/probe_pin_test.go` | Probe pin unit coverage | Negative | Exercises deterministic allocation, cap, band cleanup, dump failures, install failures, rollback, and recovery. |

### Route display and facade

Dimensions: these are read/display control paths, not the forwarding path.
Route conversion bounds nil multipath legs and degrades display on lookup
failure; no memory, concurrency, endian, vSRX, or packet-latency defect
survived.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/routing/reth.go` | Legacy RETH bond cleanup | Negative (duplicate-suppressed #4901 class) | Per-bond LinkDel is warn-only, but the root is the already-tracked teardown LinkDel failure class, not retained as a new issue. |
| `pkg/routing/routeformat.go` | Junos route rendering | Negative | CIDR matching and ECMP output are bounded by supplied route entries. |
| `pkg/routing/routes.go` | Netlink route reader | Negative | IPv4/IPv6 split, direct/blackhole handling, and multipath ifindex fallback preserve display consistency. |
| `pkg/routing/routes_multipath_test.go` | ECMP display unit coverage | Negative | Verifies all multipath legs, weights, and first-leg compatibility fields. |
| `pkg/routing/routing.go` | Manager facade | Negative | Domain ownership remains separated; Close drains keepalives before handle close. |
| `pkg/routing/routing_test.go` | VRF/PBR/monitor unit coverage | Negative | Covers VRF partial failures, transient lookup retention, PBR exactness, and copied monitor status. |
| `pkg/routing/rtproto_test.go` | Route protocol mapping coverage | Negative | FRR protocol values map to correct route display labels. |
| `pkg/routing/test_seams.go` | Cross-package test seam | Negative | Test constructor leaves unsupported route/rule domains nil and does not alter production ownership. |

### Policy-routing rules

Dimensions: all three reconcilers bound priority windows, surface list/add/delete
failures, and fail closed rather than widen PBR matches. The work is
configuration-time netlink work, uses narrow ops interfaces, and does not touch
the packet fast path. No additional parity or memory/concurrency issue survived.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/routing/rules.go` | Next-table, rib-group, PBR reconcile | Negative | Rules are cleared only inside owned bands; unsupported selectors under-steer rather than over-steer. |
| `pkg/routing/rules_test.go` | Policy-rule unit coverage | Negative | Covers stale-rule errors, dump errors, priority caps, ingress-interface scope, and representable L4 expansion. |

### Tunnel lifecycle and keepalive

Dimensions: tunnel maps are serialized; generation counters prevent stale
keepalive netlink actions; runner cancellation drains before handle closure;
address reconciliation preserves foreign link-local addresses; persistent WG
removal never deletes the link. The code keeps netlink operations out of status
and packet paths. Known WG restart/VRF-removal boundaries remain explicitly
deferred and were suppressed.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/routing/tunnel.go` | Anchor, GRE/IPIP, WG lifecycle | Negative | Reconcile-in-place preserves ifindex; ownership is retained on normal removal errors; keepalive generation/VRF/address contracts hold. |
| `pkg/routing/tunnel_anchor_keepalive_test.go` | Anchor keepalive coverage | Negative | Covers runner lifecycle, down-hold, transient lookup, and generation bump/reuse cells. |
| `pkg/routing/tunnel_keepalive.go` | ICMP keepalive prober | Negative | Uses bounded deadline, fresh nonce plus sequence, and hold-on-unknown errno classification. |
| `pkg/routing/tunnel_keepalive_test.go` | Keepalive state/concurrency coverage | Negative | Covers transition retry, generation guard, status lock scope, source binding, and recreate failure recovery. |
| `pkg/routing/tunnel_prober_test.go` | ICMP wire behavior coverage | Negative | Covers v4/v6 matching replies, nonce/sequence rejection, deadline/no-reply, and errno classification. |
| `pkg/routing/tunnel_reconcile_test.go` | Tunnel reconcile coverage | Negative | Covers address prune/retry, link-local ownership, mode handoffs, VRF claims, no-flap reuse, and Clear ownership union. |
| `pkg/routing/teardown_linkdel_4901_test.go` | Teardown regression coverage | A7-b3-F002 | Covers LinkDel retention only; it does not cover a non-not-found LinkByName error before the deletion attempt. |

### VRF lifecycle

Dimensions: VRF state is protected by a dedicated mutex, not shared with tunnel
state; ownership is retained on partial create/delete/lookup failure; no packet
path work occurs. Stable table IDs prevent vSRX and HA route churn. No finding
survived.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/routing/vrf.go` | VRF reconcile and binding | Negative | Only typed not-found is treated as absence; transient errors retain ownership. |
| `pkg/routing/vrf_stable_tableid_test.go` | VRF stable-table coverage | Negative | Sibling deletion does not recreate surviving VRFs; true table changes do. |

### XFRM/IPsec lifecycle

Dimensions: XFRM lifecycle is mutex-protected and normally returns create,
bring-up, and delete failures to the daemon; if_id collision detection prevents
cross-VPN binding. The remaining defects are control-plane fail-closed gaps,
not packet hot-path costs. Tests lack a non-XFRM name collision case.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/routing/xfrm.go` | XFRM interface reconcile | A7-b3-F002, A7-b3-F003 | Only typed not-found may drop ownership; a same-name adopted link must be an XFRM interface with the intended if_id. |
| `pkg/routing/iface_reuse_test.go` | XFRM/tunnel reuse coverage | A7-b3-F003 | Covers matching/stale if_id XFRM reuse and tunnel link reuse; lacks a non-XFRM same-name adoption test. |
| `pkg/routing/xfrm_apply_failclosed_5310_test.go` | XFRM/bond fail-closed coverage | A7-b3-F003 | Covers create and bring-up failures but not wrong-type adoption. |

### A8-b1: gRPC, REST and management surfaces (124 files)

Batch-list SHA-256: `ca4f498c5a0f4042afb7a057aceeae6c3c5f6712ab24ba6d0ff23b5521e6e8c5`.

Legend: each module was assessed for C=correctness/security/fail-closed behavior, M=memory/concurrency/truncation/leaks, V=vSRX/runtime parity, P=performance/latency, and T=test coverage. `negative` is a concrete no-surviving-finding result after that assessment. Test rows record the exercised contract and remaining gap when relevant.

### HTTP, auth, config, and lifecycle

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/api/api.go | REST shared helpers | negative | C/S/M/V/P/T: body cap, strict filters, JSON failure behavior, interface-name parsing. |
| pkg/api/api_ctx_cancel_5232_5233_test.go | cancellation tests | negative | T: route and non-cursor session scan cancellation; does not cover Prometheus collector timeout. |
| pkg/api/auth.go | REST authentication | negative | C/S/M/V/P/T: Basic/Bearer/API-key authentication and constant-time comparison. |
| pkg/api/auth_consttime_4157_test.go | auth tests | negative | T: all configured keys and unknown-user timing path. |
| pkg/api/auth_test.go | auth/config export tests | negative | T: authorization gates and export response contract. |
| pkg/api/config.go | REST config mutation/read | negative | C/S/M/V/P/T: transactional store calls, body decoding, rollback/query validation, secret redaction. |
| pkg/api/config_activate_test.go | config activate tests | negative | T: inactive AST markers through set/load/activate paths. |
| pkg/api/config_commit_test.go | config commit tests | negative | T: retired forwarding backend rejection. |
| pkg/api/config_load_bodycap_hb164_test.go | config load cap tests | negative | T: oversized and normal bodies. |
| pkg/api/config_raw_ast_redaction_test.go | config raw AST tests | negative | T: show/export/search redaction. |
| pkg/api/config_rollback_compare_strict_3443_test.go | rollback query tests | negative | T: malformed/zero rollback index is rejected. |
| pkg/api/config_secret_redaction_test.go | config secret tests | negative | T: output redaction without mutating in-memory candidate. |
| pkg/api/configstore_helper_test.go | configstore test helper | negative | T: isolated store setup. |
| pkg/api/crosssite.go | mutation CSRF guard | negative | C/S/M/V/P/T: Fetch Metadata, Origin/Referer/form guards and safe-method bypass. |
| pkg/api/crosssite_5055_test.go | cross-site tests | negative | T: trusted/same-host and cross-site cases. |
| pkg/api/server.go | listener/router lifecycle | negative | C/S/M/V/P/T: route coverage, middleware ordering, TLS persistence, slowloris bounds, graceful shutdown. |
| pkg/api/tls_test.go | TLS lifecycle tests | negative | T: generation, atomic persistence and cleanup failure paths. |
| pkg/api/write_json_4541_test.go | JSON response tests | negative | T: marshal-before-commit error behavior. |
| pkg/api/http_dos_hardening_4150_test.go | server DoS tests | A8-b1-F001 | T: verifies configured timeout/caps, but no timeout-cancels-collector integration test. |

### Diagnostics, routing, interface, and system views

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/api/dhcp.go | DHCP REST | negative | C/S/M/V/P/T: bounded decoded identifier clear; no chunked clear-all widening. |
| pkg/api/dhcp_clear_chunked_4794_test.go | DHCP clear tests | negative | T: chunked, fixed-length, and empty-body semantics. |
| pkg/api/exec_timeout.go | diagnostic process timeout | negative | C/S/M/V/P/T: finite ping/traceroute execution lifetime. |
| pkg/api/exec_timeout_test.go | diagnostic timeout tests | negative | T: successful and hung command cancellation. |
| pkg/api/diag_concurrency_5057_test.go | diagnostic limiter tests | negative | T: shared non-queueing limit across ping/traceroute. |
| pkg/api/interfaces.go | interface inventory/detail | negative | C/S/M/V/P/T: config-to-kernel naming, nil zones, unavailable counters, bounded output. |
| pkg/api/iface_name_test.go | interface-name tests | negative | T: RETH and DHCP lease-key resolution. |
| pkg/api/interface_counter_error_test.go | interface counter tests | negative | T: failed reads remain visible as unavailable rows. |
| pkg/api/routing.go | routes/OSPF/BGP REST | negative | C/S/M/V/P/T: streamed BGP JSON, cancellation, escaping, routing-manager errors. |
| pkg/api/bgp_routes_stream_4708_test.go | BGP streaming tests | negative | T: wire equivalence and non-buffering. |
| pkg/api/health.go | health/status | negative | C/S/M/V/P/T: compile/persistence degradation visibility and live session counts. |
| pkg/api/health_test.go | health tests | negative | T: failed/bootstrap/rollback state classification. |
| pkg/api/ipsec.go | IPsec status view | negative | C/S/M/V/P/T: manager error propagation and authenticated output. |
| pkg/api/system.go | system and diagnostics | negative | C/S/M/V/P/T: argv separation, bounded diagnostics, audited power actions, buffer source-of-truth. |
| pkg/api/system_argv_test.go | diagnostic argv tests | negative | T: source/VRF argument separators. |
| pkg/api/system_buffers_test.go | buffer-status tests | negative | T: userspace status authority and no misleading map fallback. |
| pkg/api/system_action_audit_4484_test.go | system action tests | negative | T: reboot/halt journal action and lock-clear validation. |
| pkg/api/types.go | REST response contracts | negative | C/S/M/V/P/T: explicit optional/zero-value fields and bounded primitive conversions. |
| pkg/api/vrrp.go | VRRP status | negative | C/S/M/V/P/T: active state lookup and empty instance behavior. |

### NAT, statistics, events, and streaming

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/api/nat.go | NAT inventory/statistics | negative | C/S/M/V/P/T: runtime NAT pool authority, no negative availability, rule counter lookup. |
| pkg/api/nat_stats_test.go | NAT statistics tests | negative | T: runtime pool fields, interface attribution, one apply-result snapshot. |
| pkg/api/stats.go | global/interface statistics | negative | C/S/M/V/P/T: kernel/user-space scopes, counter-read errors, degraded dataplane. |
| pkg/api/stats_counter_error_test.go | statistics error tests | negative | T: failed counter reads do not look like zero. |
| pkg/api/stats_global_host_inbound_3681_test.go | host-inbound global tests | negative | T: unloaded/loaded kernel-counter read behavior. |
| pkg/api/stats_global_parity_3426_test.go | stats parity tests | negative | T: NAT64 and host-inbound fields. |
| pkg/api/sse.go | SSE events/logs | negative | C/S/M/V/P/T: strict category/severity filters, context exit, bounded nonblocking EventBuffer subscribers. |
| pkg/api/sse_filter_failclosed_3383_test.go | SSE filter tests | negative | T: unknown/empty category and severity behavior. |
| pkg/api/sse_test.go | SSE event projection tests | negative | T: event/log mapping and filtering. |
| pkg/api/rest_events_forensic_3337_test.go | REST/SSE forensic tests | negative | T: common event fields and timestamp fidelity. |
| pkg/api/rest_events_limit_failclosed_4926_test.go | event limit tests | negative | T: malformed/over-cap limit rejected. |
| pkg/api/rest_events_zone0_3338_test.go | event zone-zero tests | negative | T: unknown zone remains selectable. |
| pkg/api/rest_filter_failclosed_test.go | REST filter tests | negative | T: malformed zone/port/protocol and exact event filtering. |
| pkg/api/show_text.go | text show dispatcher | negative | C/S/M/V/P/T: allowlisted topics, sorted output, sensitive SNMP rendering. |
| pkg/api/show_text_snmp_redact_5315_test.go | show-text redaction tests | negative | T: community redaction. |
| pkg/api/show_text_sorted_4712_test.go | show-text ordering tests | negative | T: deterministic output. |

### Security policy and zone surfaces

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/api/security.go | zones, policies, events, simulator | negative | C/S/M/V/P/T: fail-closed selectors, scheduler parity, nil tolerant-config nodes, counter snapshot semantics. |
| pkg/api/security_test.go | security baseline tests | negative | T: match validation and global-policy inventory. |
| pkg/api/security_default_policy_log_3670_test.go | default policy log tests | negative | T: default log state is surfaced. |
| pkg/api/security_matchpolicies_action_3375_test.go | match action tests | negative | T: dataplane/default-deny parity. |
| pkg/api/security_matchpolicies_desc_sched_3685_test.go | scheduler metadata tests | negative | T: description and scheduler fields. |
| pkg/api/security_matchpolicies_dup_3709_test.go | duplicate selector tests | negative | T: repeated scalar selectors and no-config grammar order. |
| pkg/api/security_matchpolicies_exclusion_3668_test.go | exclusion tests | negative | T: exclusion flags and stable rule identity. |
| pkg/api/security_matchpolicies_hostinbound_3627_test.go | host-inbound simulator tests | negative | T: admission token and off-host omission. |
| pkg/api/security_matchpolicies_queried_zones_3627_test.go | queried-zone tests | negative | T: query context on live/no-config paths. |
| pkg/api/security_matchpolicies_scheduler_3414_test.go | scheduler fail-closed tests | negative | T: unavailable schedule state skips scheduled rules. |
| pkg/api/security_matchpolicies_scope_3331_test.go | policy scope tests | negative | T: policy ID and declared scope. |
| pkg/api/security_matchpolicies_unknownkey_5316_test.go | selector allowlist tests | negative | T: typo rejection and known-selector acceptance. |
| pkg/api/security_policy_addr_inventory_3336_test.go | policy address tests | negative | T: exclusion/log inventory fields. |
| pkg/api/security_policy_counter_handle_3474_test.go | policy counter handle tests | negative | T: raw slice index survives nil rules. |
| pkg/api/security_policy_id_zero_3623_test.go | policy ID zero tests | negative | T: explicit matched-ID presence. |
| pkg/api/security_policy_scheduler_inventory_3624_test.go | policy scheduler inventory tests | negative | T: binding and inactive state. |
| pkg/api/security_scoped_global_3286_test.go | scoped global tests | negative | T: plural zone scope surfaced. |
| pkg/api/security_screen_inventory_3327_test.go | screen inventory tests | negative | T: checks and thresholds. |
| pkg/api/security_screen_nil_3476_test.go | nil screen/policy tests | negative | T: tolerant-config nil values do not panic. |
| pkg/api/security_zone_hostinbound_3328_test.go | zone host-inbound tests | negative | T: zone admission posture. |
| pkg/api/security_zone_local_3358_test.go | zone-local tests | negative | T: authored names are unqualified. |
| pkg/api/security_zone_nil_3493_test.go | nil zone tests | negative | T: inventory and name set tolerate nil zones. |
| pkg/api/security_zone_policy_meta_3329_test.go | zone/policy metadata tests | negative | T: description and TCP RST fields. |
| pkg/api/policies_bulk_reader_test.go | policy bulk-read tests | negative | T: one snapshot and default sentinel reuse. |
| pkg/api/policy_counters_test.go | policy counters tests | negative | T: scheduler rule counters and policy-stats gate. |
| pkg/api/zone_counter_doc_ref_test.go | zone counter docs test | negative | T: documented counter reference stays aligned. |
| pkg/api/zone_counters_hide_test.go | zone counter visibility tests | negative | T: unavailable zone counters do not fabricate alerts. |
| pkg/api/zones_policies_counter_error_test.go | security counter error tests | negative | T: REST/Prometheus errors remain explicit. |

### Session API and HA views

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/api/sessions.go | sessions/list/summary/clear | negative | C/S/M/V/P/T: strict filters, error-not-partial, HA peer status, pagination/token bounds, endian conversion. |
| pkg/api/sessions_iterator_error_test.go | iterator error tests | negative | T: REST and Prometheus do not publish partial scans. |
| pkg/api/sessions_pagination_test.go | pagination tests | negative | T: cursor/offset parity, token validation, clear-all query/body rejection. |
| pkg/api/sessions_parity_test.go | gRPC session parity tests | negative | T: REST enrichment/filter parity. |
| pkg/api/sessions_ha_scope_3423_test.go | HA session tests | negative | T: local identity, peer fanout, partial-failure reporting. |
| pkg/api/sessions_zonepair_peer_3592_test.go | HA zone-pair tests | negative | T: peer result and malformed include_peer failure. |
| pkg/api/session_summary_fields_5320_5323_test.go | session summary tests | negative | T: max capacity and explicit peer reachability status. |

### Prometheus and userspace status collector

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/api/metrics.go | collector orchestration | A8-b1-F001 | C/S/M/V/P/T: one status RPC/scrape and bounded HTTP requests; timeout does not bound collector work. |
| pkg/api/metrics_sessions.go | session gauge cache | A8-b1-F001 | C/S/M/V/P/T: cache/singleflight correctness; walk has no cancellation/deadline input. |
| pkg/api/metrics_userspace.go | userspace status projection | negative | C/S/M/V/P/T: status snapshot consistency, labels, counters, bounded configured cardinality. |
| pkg/api/metrics_counters.go | core counter collection | negative | C/S/M/V/P/T: failed reads omit samples and increment error metrics. |
| pkg/api/metrics_descriptors.go | metric descriptors | negative | C/S/M/V/P/T: descriptor/label/type uniqueness and status coverage. |
| pkg/api/metrics_nat.go | NAT metric collection | negative | C/S/M/V/P/T: runtime source-NAT authority and deterministic capacity arithmetic. |
| pkg/api/metrics_system.go | system metrics | negative | C/S/M/V/P/T: CPU delta/sample locking and proc parsing. |
| pkg/api/metrics_auth_gate_4162_test.go | metrics auth tests | negative | T: non-loopback auth gate. |
| pkg/api/metrics_cold_path_test.go | cold-path metrics tests | negative | T: layout/version/bucket/zone-label behavior. |
| pkg/api/metrics_cpu_current_4707_test.go | CPU metrics tests | negative | T: delta, first sample, and clock regression handling. |
| pkg/api/metrics_descriptor_coverage_test.go | descriptor coverage tests | negative | T: every emitted descriptor is declared. |
| pkg/api/metrics_det_pool_blocks_4752_test.go | deterministic pool tests | negative | T: pool block allocation metrics. |
| pkg/api/metrics_drop_class_4768_test.go | drop class tests | negative | T: distinct drop classification labels. |
| pkg/api/metrics_drops_scope_4508_test.go | drop scope tests | negative | T: enforcement scope help text. |
| pkg/api/metrics_flowexport_test.go | flow-export metrics tests | negative | T: collector label sets and unwired omission. |
| pkg/api/metrics_frr_degraded_test.go | FRR degradation tests | negative | T: control-plane degraded gauge. |
| pkg/api/metrics_host_inbound_accept_4759_test.go | host-inbound accept tests | negative | T: unloaded and read-error behavior. |
| pkg/api/metrics_host_inbound_addressless_3698_test.go | addressless zone tests | negative | T: nil-store and unloaded visibility. |
| pkg/api/metrics_host_inbound_ambiguous_3718_test.go | ambiguous address tests | negative | T: anomaly metric and nil-store safety. |
| pkg/api/metrics_host_inbound_junos_host_4146_test.go | junos-host deny tests | negative | T: unloaded and read-error behavior. |
| pkg/api/metrics_host_inbound_kernel_test.go | kernel host-inbound tests | negative | T: pre-dataplane collection and omission on failure. |
| pkg/api/metrics_ipsec_rebind_4899_test.go | IPsec rebind test | negative | T: pending gauge. |
| pkg/api/metrics_lo0_test.go | loopback counter tests | negative | T: pre-dataplane collection and failure omission. |
| pkg/api/metrics_nat_det_ipv6_4692_test.go | IPv6 deterministic NAT tests | negative | T: subscriber/capacity arithmetic. |
| pkg/api/metrics_neighbor_latency_test.go | neighbor latency tests | negative | T: Rust-aligned histogram bucket/cumulative behavior. |
| pkg/api/metrics_pbr_test.go | PBR metric tests | negative | T: unloaded dataplane status. |
| pkg/api/metrics_persist_degraded_test.go | persistence health tests | negative | T: config/rollback degraded gauges. |
| pkg/api/metrics_scoped_global_3286_test.go | scoped global metrics tests | negative | T: scope labels. |
| pkg/api/metrics_sessions_cache_test.go | session cache tests | A8-b1-F001 | T: TTL and singleflight are covered; no bounded/cancelled refresh test. |
| pkg/api/metrics_sessions_userspace_3929_test.go | userspace session metric tests | negative | T: live table counts in Prometheus and REST. |
| pkg/api/metrics_status_dedupe_5317_test.go | status dedupe tests | negative | T: one helper status RPC/scrape and degraded error path. |
| pkg/api/metrics_surface_a_ddns_test.go | Surface A DDNS tests | negative | T: unwired backend omission. |
| pkg/api/metrics_test.go | broad userspace metric tests | negative | T: worker, CoS, NAT, fairness and histogram projection contracts. |
| pkg/api/metrics_wireguard_test.go | WireGuard metric tests | negative | T: handshake/rekey/telemetry label set. |
| pkg/api/filter_counters_metrics_test.go | filter counter tests | negative | T: map/helper merge and post-collector error accounting. |

### A8-b2: gRPC, REST and management surfaces (125 files)

Batch-list SHA-256: `cd0bbe80c3e6b93527b21b6ff3152d436c25116008ae2ab930d7f3f5fe785e56`.

### Module review dimensions

| Module | Correctness/security/fail-open | Memory/concurrency/truncation/leaks | vSRX completeness | Performance/latency | Modularity/tests |
|---|---|---|---|---|---|
| M1 Core server, auth, runtime, config, completion | Listener clamp, fabric HMAC/allowlist ordering, mutation ownership, nil runtime adapters, and transactional config behavior were traced. `A8-b2-F004` survives because a per-RPC cancellation is treated as a connection close and destroys the shared candidate. | Lock ordering and server shutdown were negative; no retained race or stream leak. Request-vs-connection lifetime is the retained lifecycle defect. | Configure ownership, completion grammar, activation, rollback, and cluster-authority behavior were compared with Junos-style sessions. | Message receive limits and interceptor cost were checked; no hot dataplane work occurs here. | Auth/config responsibilities are separated reasonably. Holder tests omit deadline/cancel behavior on a live connection.
| M2 Diagnostics, monitor, exec, and zeroize lifecycle | Command argv construction, fabric authorization, action gating, and wipe fail-closed behavior were traced. `A8-b2-F001`/`F002` break credential erasure; `F003` permits peer recursion; `F008` leaves output byte-unbounded. | Child deadlines, pipe closure, stream cancellation, concurrency gates, recursive proxy resource growth, and durable deletion were checked. The config-dir durability issue is fixed; the same-root residual outside it was suppressed against #5197. | Monitor/proxy and factory-reset behavior were checked for dual-node/reth and re-tenant parity. | Diagnostic concurrency and runtime ceilings are bounded, but child output allocation is not byte-bounded. | Helpers have seams and focused tests; missing tests cover root markers, identity-read errors, both-secondary proxying, and huge single-line output.
| M3 Structured state, counters, sessions, NAT, routing, DHCP | Request validation, backend error propagation, clear semantics, pagination, counter provenance, and nil managers were traced. `A8-b2-F007` suppresses NAT backend failures; `F010` emits an invalid PD-only lease address. | Session iteration errors and bounded/unbounded snapshots were checked. The unbounded filtered clear was suppressed as a prior finding. | HA node selection, NAT rule/pool reporting, DHCPv6 PD, screen/global stats, and route inventory were checked. | Full-table scans and counter fan-out were inspected; no new retained hot-path issue in this module. | Runtime accessor interfaces are useful seams. NAT failure tests and PD-only structured-output tests are absent.
| M4 Policy/security matching and validation | Zone scope, host-inbound, scheduler, route-drop, protocol, action, exclusion, nil slot, and counter-error behavior were inspected. No new finding survived; malformed inputs generally fail closed. | Bulk readers and matcher inputs showed no retained race, leak, or truncation defect. | Tests cover many Junos/vSRX matching and display edge cases, including global and zone-local policy semantics. | Matching RPCs are control-plane scans; no per-packet work or new unbounded materialization survived review. | The test matrix is broad but fragmented across issue-specific files; no correctness bug was inferred from organization alone.
| M5 ShowText and operational renderers | Dispatch, selectors, secret display, counter warnings, peer forwarding, and renderer nil-state behavior were traced. `A8-b2-F005`, `F006`, `F008`, and `F009` survive. | Top-session heap retention is bounded but performs two heap allocations per visited session; renderer output and child capture were checked for byte limits. | Chassis, interfaces, policies, zones, DHCP, routing, AppID, CoS, firewall, events, and security output were compared with expected operational semantics. | `A8-b2-F005` can create about 20 million allocations at the documented 10-million-session scale. Other renderers are cold-path. | Topic dispatch is split across focused files and tests. Missing negative tests cover URL redaction, invalid route destinations, allocation counts, and output bytes.

### Complete per-file ledger

| # | Path | Module/subsystem | Result | Invariant checked |
|---:|---|---|---|---|
| 1 | `pkg/grpcapi/apply_result.go` | M1 / applied snapshot | negative | Applied-result publication and reads preserve a coherent pointer under the server lock. |
| 2 | `pkg/grpcapi/clear_sessions_errors_test.go` | M3 / session clear | negative | Local and peer clear failures are surfaced instead of reported as success. |
| 3 | `pkg/grpcapi/clear_sessions_peer_nodeid_3423_test.go` | M3 / HA session clear | negative | Peer node identity and clear result attribution remain distinct. |
| 4 | `pkg/grpcapi/clear_sessions_reversekey_test.go` | M3 / session clear | negative | Filtered clear removes forward/reverse companions consistently; unbounded snapshots were duplicate-suppressed as D01. |
| 5 | `pkg/grpcapi/complete_utf8_pos_4970_test.go` | M1 / completion | negative | Byte positions cannot split UTF-8 and broaden or corrupt completion. |
| 6 | `pkg/grpcapi/completion_test.go` | M1 / completion | negative | Command-tree traversal, prefixes, and candidate ordering remain deterministic. |
| 7 | `pkg/grpcapi/completion_typed_leaf_test.go` | M1 / completion | negative | Typed leaf providers receive the right config and token context. |
| 8 | `pkg/grpcapi/config_lock_holder_5059_test.go` | M1 / config ownership | negative | Non-holders cannot mutate the shared candidate; cancellation lifecycle is not covered (`A8-b2-F004`). |
| 9 | `pkg/grpcapi/configstore_helper_test.go` | M1 / config fixtures | negative | Test store creation/load uses isolated state and preserves active/candidate separation. |
| 10 | `pkg/grpcapi/diag_concurrency_5057_test.go` | M2 / diagnostics | negative | Concurrent diagnostic children are capped and admission fails closed. |
| 11 | `pkg/grpcapi/exec_timeout.go` | M2 / child execution | `A8-b2-F008` | Runtime and wait-drain bounds exist, but captured stdout/stderr has no byte ceiling. |
| 12 | `pkg/grpcapi/exec_timeout_test.go` | M2 / child execution tests | negative | Deadlines, stderr separation, WaitDelay, and line-count clamp are tested; byte-bound behavior is absent. |
| 13 | `pkg/grpcapi/fabric_auth.go` | M1 / HA fabric auth | negative | Token verification, constant-time comparison, key availability, and rollout state were checked. |
| 14 | `pkg/grpcapi/flow_cluster_counter_error_test.go` | M3 / flow telemetry | negative | Cluster-counter read errors remain visible rather than clean zero. |
| 15 | `pkg/grpcapi/global_stats_counter_error_test.go` | M3 / global telemetry | negative | Global counter failures produce an explicit unavailable/incomplete signal. |
| 16 | `pkg/grpcapi/global_stats_screen_keys_3343_test.go` | M3 / screen counters | negative | Structured screen detail uses canonical, stable reason keys. |
| 17 | `pkg/grpcapi/iface_name_test.go` | M3 / interface identity | negative | Logical/kernel interface-name conversion is canonical and bounded. |
| 18 | `pkg/grpcapi/interface_counter_error_test.go` | M3 / interface telemetry | negative | Interface counter failures are not rendered as healthy zeros. |
| 19 | `pkg/grpcapi/pagination_test.go` | M3 / pagination | negative | Cursor/offset bounds and continuation behavior avoid skip/duplication locally; peer cursor defect was duplicate-suppressed as D05. |
| 20 | `pkg/grpcapi/policies_bulk_reader_test.go` | M4 / policy telemetry | negative | Bulk counter errors are retained and policy rows are not silently fabricated. |
| 21 | `pkg/grpcapi/runtime.go` | M1 / runtime adapters | negative | Dataplane/session/telemetry accessor fallbacks preserve nil and loaded-state semantics. |
| 22 | `pkg/grpcapi/runtime_canary_test.go` | M1 / runtime canary | negative | The production surface remains bound to the userspace dataplane rather than retired forwarding paths. |
| 23 | `pkg/grpcapi/server.go` | M1 / server lifecycle | `A8-b2-F004` | Listener trust boundaries and shutdown are bounded; unary request cancellation is not a connection-lifetime signal. |
| 24 | `pkg/grpcapi/server_bgp_status_ip_guard_4588_test.go` | M3 / BGP status | negative | Malformed peer addresses cannot panic or masquerade as valid status keys. |
| 25 | `pkg/grpcapi/server_cluster.go` | M3 / HA control | negative | Failover request validation and peer-state reporting were traced; missing-node behavior was duplicate-suppressed as D02. |
| 26 | `pkg/grpcapi/server_cluster_monitor_status_4480_test.go` | M3 / HA monitor status | negative | Interface-monitor status is represented with correct RG/node context. |
| 27 | `pkg/grpcapi/server_cluster_test.go` | M3 / HA control tests | negative | Cluster status and failover RPC response/error behavior remain deterministic. |
| 28 | `pkg/grpcapi/server_config.go` | M1 / config RPCs | negative (trace support for `A8-b2-F004`) | RG0 authority, holder identity, mutation/commit mapping, and exit semantics were traced. |
| 29 | `pkg/grpcapi/server_config_activate_test.go` | M1 / activation | negative | Activation parses the command verb exactly and does not accept prefix confusion. |
| 30 | `pkg/grpcapi/server_config_redaction_test.go` | M1 / config secrecy | negative | Configuration responses redact secret leaves without destroying useful structure. |
| 31 | `pkg/grpcapi/server_config_test.go` | M1 / config lifecycle | negative | Set/delete/commit/rollback and retired-forwarding rejection preserve transaction boundaries. |
| 32 | `pkg/grpcapi/server_dhcp.go` | M3 / DHCP inventory | `A8-b2-F010` | DHCPv6 PD-only leases must not serialize an invalid address token. |
| 33 | `pkg/grpcapi/server_diag.go` | M2 / diagnostics | negative | Diagnostic command streaming uses argv, concurrency admission, cancellation, and bounded scanners. |
| 34 | `pkg/grpcapi/server_diag_argv_test.go` | M2 / diagnostics tests | negative | User fields remain argv elements rather than shell syntax. |
| 35 | `pkg/grpcapi/server_diag_monitor.go` | M2 / interface monitor | `A8-b2-F003` | Peer forwarding must terminate even when neither node reports RG primary. |
| 36 | `pkg/grpcapi/server_diag_monitor_test.go` | M2 / monitor tests | negative | Dataplane counter projection is correct; peer recursion states are not exercised. |
| 37 | `pkg/grpcapi/server_diag_ping.go` | M2 / ping/traceroute | negative | Counts, VRF, destination validation, and execution budgets are applied before spawn. |
| 38 | `pkg/grpcapi/server_diag_scanner_leak_5060_test.go` | M2 / stream cleanup | negative | Send failure closes the pipe and cancels the child/scanner goroutines. |
| 39 | `pkg/grpcapi/server_diag_stream_test.go` | M2 / stream tests | negative | Child termination and pipe backpressure do not strand diagnostic goroutines. |
| 40 | `pkg/grpcapi/server_diag_system_action.go` | M2 / lifecycle actions | negative (trace support for `A8-b2-F001`, `F002`) | Destructive verbs are explicit and zeroize errors gate the success response. |
| 41 | `pkg/grpcapi/server_diag_zeroize.go` | M2 / factory reset | `A8-b2-F001`, `A8-b2-F002` | Every xpf-managed credential must be revoked, uncertain identity must retain retry state, and success must mean complete erasure. |
| 42 | `pkg/grpcapi/server_fabric_allowlist_4122_test.go` | M1 / fabric authorization | negative | Fabric methods are deny-by-default and destructive RPCs never reach handlers. |
| 43 | `pkg/grpcapi/server_fabric_auth_4107_test.go` | M1 / fabric authentication | negative | Valid/current tokens pass, invalid/downgrade tokens fail, and auth precedes authorization. |
| 44 | `pkg/grpcapi/server_grpc_loopback_clamp_5035_test.go` | M1 / listener boundary | negative | The unauthenticated primary listener is forced to family-matching loopback. |
| 45 | `pkg/grpcapi/server_helpers.go` | M3 / shared helpers | `A8-b2-F007` | NAT session iteration errors must not collapse into partial clean totals. |
| 46 | `pkg/grpcapi/server_input_validation_test.go` | M1 / request validation | negative | Completion positions and malformed request fields fail closed. |
| 47 | `pkg/grpcapi/server_matchpolicies_action_3375_test.go` | M4 / policy match | negative | Policy action rendering and filtering preserve permit/deny/reject semantics. |
| 48 | `pkg/grpcapi/server_matchpolicies_desc_sched_3685_test.go` | M4 / policy match | negative | Description and scheduler metadata survive structured matching. |
| 49 | `pkg/grpcapi/server_matchpolicies_exclusion_3668_test.go` | M4 / policy match | negative | Address exclusions do not widen policy matches. |
| 50 | `pkg/grpcapi/server_matchpolicies_hostinbound_3627_test.go` | M4 / host-inbound policy | negative | Host-inbound traffic is distinguished from transit policy. |
| 51 | `pkg/grpcapi/server_matchpolicies_queried_zones_3627_test.go` | M4 / policy scope | negative | Requested from/to zones constrain matching and output attribution. |
| 52 | `pkg/grpcapi/server_matchpolicies_routedrop_4413_test.go` | M4 / route-drop policy | negative | Route-drop actions remain visible and are not recast as ordinary deny. |
| 53 | `pkg/grpcapi/server_matchpolicies_scheduler_3414_test.go` | M4 / scheduler state | negative | Scheduler-active/inactive states gate policy matching as designed. |
| 54 | `pkg/grpcapi/server_matchpolicies_scope_3331_test.go` | M4 / policy scope | negative | Global and zone-pair scope selection does not silently broaden. |
| 55 | `pkg/grpcapi/server_missing_zone_3355_test.go` | M4 / policy validation | negative | Missing zone references fail closed instead of matching zone zero. |
| 56 | `pkg/grpcapi/server_nat.go` | M3 / NAT telemetry | `A8-b2-F007` | Port, rule, and session telemetry backend failures must remain distinguishable from zero activity. |
| 57 | `pkg/grpcapi/server_nat_test.go` | M3 / NAT tests | negative | Pool/rule/session aggregation works for successful stores; injected read failures are not covered. |
| 58 | `pkg/grpcapi/server_packet_drop_validation_3382_test.go` | M4 / packet-drop stream | negative | Invalid selectors fail before subscription and cancellation propagates correctly. |
| 59 | `pkg/grpcapi/server_policy_id_zero_3623_test.go` | M4 / policy identity | negative | Policy ID zero is handled as a valid/sentinel case without accidental omission. |
| 60 | `pkg/grpcapi/server_proto_validation_test.go` | M4 / protocol validation | negative | Unknown or out-of-range protocols return InvalidArgument rather than wildcarding. |
| 61 | `pkg/grpcapi/server_recvsize_hb164_test.go` | M1 / message bounds | negative | Oversized inbound messages are rejected at the server boundary. |
| 62 | `pkg/grpcapi/server_rollback_negative_n_4589_test.go` | M1 / rollback validation | negative | Negative rollback indices are rejected rather than wrapping or selecting zero. |
| 63 | `pkg/grpcapi/server_routing.go` | M3 / route inventory | negative | Nil manager, route errors, protocol/address conversion, and pagination fail explicitly. |
| 64 | `pkg/grpcapi/server_screen_inventory_3327_test.go` | M4 / screen inventory | negative | Structured screen inventory uses configured names and canonical counters. |
| 65 | `pkg/grpcapi/server_security_nil_3476_test.go` | M4 / nil security slots | negative | Present-but-nil policy/screen entries cannot panic operational RPCs. |
| 66 | `pkg/grpcapi/server_sessions.go` | M3 / sessions | negative (duplicates D01, D05, D06, D07 suppressed) | Filtered clear, peer pagination, HA label attribution, and interface filters were checked against prior same-root findings. |
| 67 | `pkg/grpcapi/server_sessions_test.go` | M3 / sessions tests | negative | Session filters, counters, clear behavior, and result shaping retain local correctness. |
| 68 | `pkg/grpcapi/server_show.go` | M5 / ShowText dispatch | `A8-b2-F008` | Topic dispatch validates selectors, but log output remains byte-unbounded after a line clamp. |
| 69 | `pkg/grpcapi/server_show_appid.go` | M5 / AppID display | negative | Catalog/status rendering handles disabled, absent, and populated runtime state. |
| 70 | `pkg/grpcapi/server_show_appid_test.go` | M5 / AppID tests | negative | AppID output names, counts, and nil state remain stable. |
| 71 | `pkg/grpcapi/server_show_chassis.go` | M5 / chassis display | negative | Chassis inventory and forwarding state preserve node/device identity. |
| 72 | `pkg/grpcapi/server_show_chassis_forwarding_test.go` | M5 / HA forwarding display | negative | Peer forwarding has an explicit no-peer guard; this contrast supports `A8-b2-F003`. |
| 73 | `pkg/grpcapi/server_show_cluster_text.go` | M5 / cluster text | negative | RG/node state, monitor, and failover text use coherent cluster snapshots. |
| 74 | `pkg/grpcapi/server_show_compare_strict_3443_test.go` | M5 / config compare | negative | Reserved compare selectors do not silently fall through to candidate diff. |
| 75 | `pkg/grpcapi/server_show_cos_gap7_test.go` | M5 / CoS display | negative | Unsupported/absent CoS state remains explicit rather than fabricated. |
| 76 | `pkg/grpcapi/server_show_device_map.go` | M5 / device map | negative | Authored/logical/kernel names and unmapped devices are rendered deterministically. |
| 77 | `pkg/grpcapi/server_show_dhcp_lldp_snmp.go` | M5 / services display | negative | DHCP/LLDP/SNMP nil and runtime error paths were checked; prior clean-empty DHCP error was duplicate D08. |
| 78 | `pkg/grpcapi/server_show_events.go` | M5 / event display | negative | Event selectors, zone IDs, limits, and historical fields preserve query intent. |
| 79 | `pkg/grpcapi/server_show_events_forensic_3337_test.go` | M5 / forensic events | negative | Forensic metadata and timestamps remain visible and ordered. |
| 80 | `pkg/grpcapi/server_show_events_historical_zone_3335_test.go` | M5 / historical events | negative | Historical zone names survive current-config changes. |
| 81 | `pkg/grpcapi/server_show_events_zone0_3338_test.go` | M5 / event zones | negative | Zone ID zero is represented without being mistaken for missing data. |
| 82 | `pkg/grpcapi/server_show_events_zone_3334_test.go` | M5 / event zones | negative | Invalid zone IDs fail explicitly and valid IDs map canonically. |
| 83 | `pkg/grpcapi/server_show_firewall.go` | M5 / firewall display | negative | Filter/policer counters carry errors into warnings and preserve effective terms. |
| 84 | `pkg/grpcapi/server_show_firewall_effective_4967_test.go` | M5 / firewall tests | negative | Effective firewall terms reflect inherited/compiled behavior rather than authored-only state. |
| 85 | `pkg/grpcapi/server_show_firewall_test.go` | M5 / firewall tests | negative | Counter, policer color, and screen reason rendering remains stable. |
| 86 | `pkg/grpcapi/server_show_flow.go` | M5 / flow display | `A8-b2-F005` | Top-K retention must also bound per-visited-session allocations and GC pressure. |
| 87 | `pkg/grpcapi/server_show_forwarding.go` | M5 / forwarding display | negative | Peer ShowText recursion is prevented with outgoing metadata and bounded dialing. |
| 88 | `pkg/grpcapi/server_show_forwarding_adapter_test.go` | M5 / forwarding tests | negative | Userspace and generic dataplane status adapters preserve capability selection. |
| 89 | `pkg/grpcapi/server_show_golden_test.go` | M5 / golden output | negative | Broad topic dispatch remains non-panicking and stable; volatile fields are normalized. |
| 90 | `pkg/grpcapi/server_show_interfaces.go` | M5 / interface display | negative | Structured interface inventory preserves logical/kernel identity and counter errors. |
| 91 | `pkg/grpcapi/server_show_interfaces_reth_4328_test.go` | M5 / reth display | negative | Redundant Ethernet member/state rendering uses the owning RG. |
| 92 | `pkg/grpcapi/server_show_interfaces_text.go` | M5 / interface text | negative | Interface detail/terse/queue output handles missing devices and telemetry errors explicitly. |
| 93 | `pkg/grpcapi/server_show_nat.go` | M5 / NAT text | negative | Text NAT rendering shares pool/rule/session semantics and emits counter warnings. |
| 94 | `pkg/grpcapi/server_show_nat_shared_test.go` | M5 / NAT shared tests | negative | Shared NAT calculations remain consistent across structured and text output on success. |
| 95 | `pkg/grpcapi/server_show_nat_test.go` | M5 / NAT text tests | negative | NAT rule-set, pool, and persistent-binding output remains deterministic. |
| 96 | `pkg/grpcapi/server_show_policies_addr_inventory_3336_test.go` | M5 / policy addresses | negative | Address inventory includes scoped/global objects without leaking synthetic names. |
| 97 | `pkg/grpcapi/server_show_policies_hitcount_gate_test.go` | M5 / policy counters | negative | Hit counts obey configured gates and `then count` semantics. |
| 98 | `pkg/grpcapi/server_show_policies_hitcount_globals_test.go` | M5 / global policy counters | negative | Global policies remain present in hit-count output with correct scope. |
| 99 | `pkg/grpcapi/server_show_policies_scheduler_3062_test.go` | M5 / scheduler display | negative | Policy scheduler state and next transitions are represented consistently. |
| 100 | `pkg/grpcapi/server_show_policies_text.go` | M5 / policy text | negative | Policy detail/hit-count joins, counter errors, scopes, and address expansion fail visibly. |
| 101 | `pkg/grpcapi/server_show_policies_text_exclusion_3667_test.go` | M5 / policy exclusions | negative | Excluded address members remain visibly distinguished in text output. |
| 102 | `pkg/grpcapi/server_show_policies_text_scoped_global_3357_test.go` | M5 / scoped globals | negative | Filtered detail retains applicable scoped global policies. |
| 103 | `pkg/grpcapi/server_show_policies_thencount_3074_test.go` | M5 / policy counters | negative | `then count` overrides the global statistics display gate only for that policy. |
| 104 | `pkg/grpcapi/server_show_policies_zone_local_3358_test.go` | M5 / zone-local names | negative | Synthetic zone-local qualifiers are removed from operator-facing names. |
| 105 | `pkg/grpcapi/server_show_rollback_zero_n_4556_test.go` | M5 / rollback display | negative | Rollback zero and count zero retain explicit, non-wrapping semantics. |
| 106 | `pkg/grpcapi/server_show_routes_text.go` | M5 / route text | `A8-b2-F009` (duplicate D03 also suppressed) | Malformed destinations must be rejected rather than reported as a valid lookup miss. |
| 107 | `pkg/grpcapi/server_show_rpm_test.go` | M5 / RPM display | negative | Probe status/results and absent runtime state remain explicit. |
| 108 | `pkg/grpcapi/server_show_screen_inventory_text_3327_test.go` | M5 / screen text | negative | Screen names and canonical reason inventory appear in text output. |
| 109 | `pkg/grpcapi/server_show_security_log_zone_3547_test.go` | M5 / security logs | negative | Unknown zone selectors fail closed rather than widening a log query. |
| 110 | `pkg/grpcapi/server_show_security_text.go` | M5 / security display | `A8-b2-F006` | Operational dynamic-address output must redact credential-bearing URL components. |
| 111 | `pkg/grpcapi/server_show_security_wireguard_test.go` | M5 / WireGuard display | negative | WireGuard peers, keys/status, and absent state are rendered without private-key exposure. |
| 112 | `pkg/grpcapi/server_show_status.go` | M5 / system status | negative | Process/filesystem/socket/journal command errors do not fabricate healthy state; shared output-byte risk is `F008`. |
| 113 | `pkg/grpcapi/server_show_status_3929_test.go` | M5 / status tests | negative | Runtime status fields and missing-provider output remain stable. |
| 114 | `pkg/grpcapi/server_show_system.go` | M5 / system display | negative | Time/NTP/DNS/login/system renderers handle command failure and redact configured secrets. |
| 115 | `pkg/grpcapi/server_show_system_buffers_test.go` | M5 / buffer display | negative | Buffer/runtime metrics use bounded, coherent snapshots and stable labels. |
| 116 | `pkg/grpcapi/server_show_test_routing_unknownkey_4589_test.go` | M5 / route test parser | negative | Unknown selector keys fail before routing lookup; invalid destination values remain uncovered (`F009`). |
| 117 | `pkg/grpcapi/server_show_test_zone_selector_4814_test.go` | M5 / policy test parser | negative | Missing/unknown zone selectors cannot silently widen test-policy queries. |
| 118 | `pkg/grpcapi/server_show_testpolicy_srcport_test.go` | M5 / policy test parser | negative | Malformed source ports produce diagnostics and never wildcard-match. |
| 119 | `pkg/grpcapi/server_show_zones.go` | M5 / zones display | negative | Zone inventory joins interfaces, host-inbound, screens, and policies without nil panics. |
| 120 | `pkg/grpcapi/server_show_zones_default_policy_3363_test.go` | M5 / default policy | negative | Zone default policy is displayed from effective semantics. |
| 121 | `pkg/grpcapi/server_show_zones_default_policy_log_3670_test.go` | M5 / default-policy logging | negative | Default-policy logging action remains visible. |
| 122 | `pkg/grpcapi/server_show_zones_explicit_any_3680_test.go` | M5 / wildcard zones | negative | Explicit any-side global policies appear only in affected zone detail. |
| 123 | `pkg/grpcapi/server_show_zones_hostinbound_3328_test.go` | M5 / host-inbound | negative | Configured host-inbound services/protocols are represented per interface/zone. |
| 124 | `pkg/grpcapi/server_show_zones_hostinbound_display_3654_test.go` | M5 / host-inbound display | negative | Display names and inherited host-inbound entries remain operator-facing and stable. |
| 125 | `pkg/grpcapi/server_show_zones_lifeline_3682_test.go` | M5 / lifeline policy | negative | Lifeline management access remains visible and distinct from ordinary host-inbound rules. |

### A8-b3: gRPC, REST and management surfaces (32 files)

Batch-list SHA-256: `3651792c6fe59fafa75d67accd0b79c882f4fe6e8d14bc14f77f0875c55a3db0`.

### Zone, policy, and text surfaces

Correctness/security covered nil tolerant-config entries, strict selector grammar, policy-tier and scheduler fidelity, fail-closed counter errors, and host-inbound visibility. Memory/concurrency covered map iteration, output growth, and sequential counter reads. vSRX parity covered global/default tiers, scheduler metadata, lifelines, and unavailable userspace counters. Performance covered sorting, policy scans, and helper-call volume. Modularity/test coverage covered the shared policy/host-inbound presenters and positive, negative, nil, and backend-error tests.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/grpcapi/server_show_zones_metadata_3684_test.go` | Zone-detail policy metadata | negative | Runtime IDs, scheduler state, log/count/exclusion modifiers, and default-policy metadata remain visible without extra hot-path work. |
| `pkg/grpcapi/server_show_zones_policy_tiers_3658_test.go` | Zone-detail policy precedence | negative | Zone-pair, applicable global, and default tiers render in runtime order without leaking scoped globals. |
| `pkg/grpcapi/server_show_zones_scheduler_inventory_3624_test.go` | Structured scheduler inventory | negative | Binding and active/inactive state are carried; the unknown-provider fail-open display candidate was duplicate-suppressed against tracked #3062/#3624. |
| `pkg/grpcapi/server_show_zones_scoped_global_3286_test.go` | Scoped global inventory | negative | Structured and text surfaces retain global-policy zone scope. |
| `pkg/grpcapi/server_show_zones_test.go` | Policy counters | negative | Counter handles span policy sets, `then count` overrides the global gate, and global/zone-pair counters remain distinct. |
| `pkg/grpcapi/server_show_zones_text.go` | Zone detail and `test-zone` text | negative | Nil config values, sorted zones, unavailable/error counters, shared policy summaries, and strict selector grammar were checked; repeated-selector last-win was duplicate-suppressed. |
| `pkg/grpcapi/server_testpolicy_dup_3709_test.go` | Policy test parser | negative | Repeated selectors fail rather than silently last-win. |
| `pkg/grpcapi/server_testpolicy_strictness_3696_test.go` | Policy test parser | negative | Missing `=`, unknown keys, and empty values do not widen a simulated policy query. |
| `pkg/grpcapi/server_zone_nil_3493_test.go` | Tolerant config inventory | negative | Nil zone map values cannot panic zone, interface, completion, screen, or session-filter paths. |
| `pkg/grpcapi/test_commands_test.go` | Policy simulator bridge | negative | ShowText uses the shared runtime-order matcher for predefined apps, globals, and default policy. |
| `pkg/grpcapi/text_filter_flood_counter_error_test.go` | Text counter observability | negative | Policy, zone, filter, and flood read failures remain visible instead of becoming authoritative zeros. |
| `pkg/grpcapi/zone_flood_counters_hide_test.go` | Unsupported userspace counters | negative | `ErrCounterNotPopulated` renders as unavailable, not zero or a false bridge warning. |
| `pkg/grpcapi/zonepair_summary_3592_test.go` | Zone-pair session summary | negative | Forward-only aggregation, iterator errors, recursion prevention, node identity, and peer fan-out are correct. |
| `pkg/grpcapi/zones_policies_counter_error_test.go` | Structured counter errors | negative | GetZones/GetPolicies fail on genuine reads; the mixed-sentinel candidate was refuted because the sole runtime manager stores both directions atomically and returns no direction-specific generic error. |

### Sessions and HA views

Correctness/security covered filter narrowing, endian conversion, reverse-entry exclusion/merge, iterator error propagation, and HA completeness. Memory/concurrency covered cursor/full scans and candidate ownership. vSRX parity covered source-port AppID matching, interface resolution, summaries, and top-20 behavior. Performance found an O(N) allocation regression despite bounded heap retention. Modularity/test coverage checked shared filters and session-entry helpers, with a surviving schema/handler gap for peer-fetch completeness.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/grpcapi/session_app_srcport_3428_test.go` | Session AppID enrichment | negative | Network-order source and destination ports are both threaded into tuple resolution. |
| `pkg/grpcapi/session_egress_drift_4650_test.go` | Session egress presentation | negative | IPv4/IPv6 gRPC entries ignore stale ifindex-zero mappings and match REST fallback order. |
| `pkg/grpcapi/session_filter_3439_test.go` | Session request validation | negative | Invalid protocols and negative offsets fail both cursor and legacy paths. |
| `pkg/grpcapi/session_filter_test.go` | Session filtering | negative | Prefix/port/zone narrowing, numeric protocols, SNAT pool membership, and clear-path fail-closed validation hold. |
| `pkg/grpcapi/session_summary_fields_5320_5323_test.go` | Session/zone-pair summary schema | A8-b3-F003 | Summary RPCs expose peer completeness and dynamic capacity, highlighting that GetSessions still cannot report peer-fetch failure. |
| `pkg/grpcapi/sessions_iterator_error_test.go` | Session iteration failures | negative | Legacy list and summary RPCs reject partial backend scans. |
| `pkg/grpcapi/sessions_top_5319_test.go` | Top-session selection | A8-b3-F004 | Ranking and enrichment are bounded to K, but tests do not bound per-candidate IP allocation. |

### System actions and shutdown

Correctness/security covered failover target validation, loop prevention, userspace injection decoding, destructive action audit ordering, and dynamic DNS dispatch. Memory/concurrency covered deferred child processes and bounded gRPC shutdown. vSRX parity covered reboot/halt/power-off/zeroize and failover semantics. Performance covered stream shutdown deadlines and control-socket calls. Modularity/test coverage found that power-action seams prove invocation but not command acceptance or completion.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/grpcapi/server_shutdown_monitor_4910_test.go` | gRPC lifecycle | negative | A stuck stream cannot hold shutdown beyond `grpcStopTimeout`, while idle shutdown remains prompt. |
| `pkg/grpcapi/system_action_failover_node_4693_test.go` | HA failover action | negative | Unsupported node IDs are rejected before proxying; the empty-node suffix issue was duplicate-suppressed against the prior missing-target failover root cause. |
| `pkg/grpcapi/system_action_journal_4108_test.go` | Destructive action audit | A8-b3-F005 | Tests establish pre-action journal writes and invocation, but the deferred command result is discarded. |
| `pkg/grpcapi/system_action_test.go` | System action dispatch | A8-b3-F005 | Peer routing, recursion guards, injection metadata, and DDNS dispatch pass; reboot/halt/power-off still return before an unchecked `systemctl` result. |

### Zeroize lifecycle

Correctness/security covered config SSOT, rollback/journal/TLS/rendered secrets, provisioned login accounts, partial failures, and retry identity. Memory/concurrency covered filesystem ordering, TOCTOU surfaces, and process-lifetime state. vSRX parity covered factory-reset completeness and operator-owned-file preservation. Performance covered bounded directory walks and external commands. Modularity/test coverage found two production orchestration gaps outside the otherwise strong helper-level tests.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/grpcapi/zeroize_configdb_4576_test.go` | Config factory reset | A8-b3-F001 | The helper erases an explicitly supplied directory, but the gRPC production caller never supplies the daemon's configured path. |
| `pkg/grpcapi/zeroize_durable_5197_test.go` | Durable config erasure | negative | Key unlink precedes ciphertext removal, both directory barriers are ordered, and sync failures propagate. |
| `pkg/grpcapi/zeroize_login_4598_test.go` | Login-account teardown | A8-b3-F002 | Normal UID ownership and `userdel` retry are tested; unreadable passwd/corrupt-marker provenance is not fail-closed. |
| `pkg/grpcapi/zeroize_rendered_4585_test.go` | Rendered secret teardown | negative | XPF-owned FRR, swanctl, and Kea material is removed while unmanaged FRR content survives; the generic missing-fsync candidate was duplicate-suppressed against #5197. |
| `pkg/grpcapi/zeroize_tls_4599_test.go` | TLS key teardown | negative | The generated REST TLS keypair and directory are removed without deleting unrelated config-directory files. |

### Generated protobuf and gRPC contracts

Correctness/security covered field presence, signed/narrowing inputs, recursive peer responses, destructive/streaming method exposure, and handler-to-method mapping. Memory/concurrency covered standard protobuf message state, descriptor `sync.Once`, and stream ownership. vSRX parity covered structured policy/session/HA fields. Performance covered message bounds and streaming shape. Modularity/test coverage confirmed standard generated stubs; the GetSessions response schema lacks the completeness state already present on both summary responses.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/grpcapi/xpfv1/xpf.pb.go` | Protobuf message/schema binding | A8-b3-F003 | Generated descriptors and optional scalar presence are standard, but `GetSessionsResponse` has only `peer`, with no status/error field for a requested but failed peer leg. |
| `pkg/grpcapi/xpfv1/xpf_grpc.pb.go` | gRPC client/server binding | negative | All 51 unary/stream methods map consistently through interceptors and standard generated handlers; no custom unsafe/resource code survives. |

### A9-b1: Observability, telemetry and event processing (104 files)

Batch-list SHA-256: `af0ece5a897534672f5c0f3d75995308af062057821eb137c0a561ee8cdb36d4`.

### Event engine

Dimensions checked: transactional remediation and stale-policy rejection; queue ownership, shutdown, and atomic counters; bounded retry/timer behavior; config/runtime parity for cooldown, temporal matching, and attributes; hot-path indexing/allocation. The queue uses a single worker and bounded channel, but its concurrent drain/refill violates the admitted-action preservation invariant (F001). The remaining paths fail closed on malformed plans, stale policies, and absent stores. Test coverage lacks a producer-interleaving test while `supersede` refills a full queue.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/eventengine/engine.go` | policy evaluator and remediation queue | A9-b1-F001 | Admitted unrelated actions remain FIFO and cannot be dropped by another policy's supersede. |
| `pkg/eventengine/engine_4423_test.go` | policy evaluation regressions | negative | ANDed within clauses, regex cache/index routing, and nil store fail closed. |
| `pkg/eventengine/engine_cooldown_rev_5311_test.go` | cooldown revisions | negative | Successful commits stamp only the authorizing semantic generation. |
| `pkg/eventengine/engine_edge_trigger_3756_test.go` | temporal trigger | negative | Trigger-on is edge-triggered and re-arms only below threshold. |
| `pkg/eventengine/engine_inclusive_until_3756_test.go` | temporal trigger | negative | Trigger-until includes the terminal event and stops afterwards. |
| `pkg/eventengine/engine_integration_test.go` | transactional remediation | negative | Candidate mutation is atomic, lock retries bounded, stale work rejected, and queue order tests cover non-racing cases. |
| `pkg/eventengine/engine_stale_revalidate_3750_test.go` | stale queued work | negative | Removed, redefined, or cooldown-suppressed policies cannot commit queued work. |
| `pkg/eventengine/engine_test.go` | attributes matching | negative | Invalid/unknown fields fail closed and compiled regexes preserve event scoping. |
| `pkg/eventengine/engine_window_test.go` | temporal windows | negative | Sliding windows remain bounded and concurrent matching does not duplicate policy evaluation. |
| `pkg/eventengine/engine_within_failclosed_3751_test.go` | temporal validation | negative | Zero threshold/window fails closed while no-clause policies retain normal firing. |

### Dynamic feeds

Dimensions checked: content canonicalization and fail-closed empty/invalid responses; lock ownership and snapshot handoff; line/body/entry/sample bounds; retained-last-good memory and callback behavior; dynamic-address binding completeness. Fetches cap bodies, entries, scanner tokens, and retained invalid-line diagnostics; snapshots are deep-copied and failures retain last good state by default. No surviving issue.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/feeds/feeds.go` | feed manager | negative | Complete plan swap, cancellation, retained snapshots, deep-copy reads, and bounded parsing prevent partial fail-open state. |
| `pkg/feeds/feeds_bindings_test.go` | binding projection | negative | Feed unions are sorted/deduped, deep copied, and empty bindings remain fail closed. |
| `pkg/feeds/feeds_dup_name_4913_test.go` | configuration planning | negative | Duplicate names resolve deterministically without orphan refresh loops. |
| `pkg/feeds/feeds_samplecap_4922_test.go` | diagnostics bounds | negative | Invalid samples are escaped and bounded per entry and in aggregate. |
| `pkg/feeds/feeds_sizecap_3934_test.go` | fetch limits | negative | Oversize bodies/entry counts and slow responses retain last-good state. |
| `pkg/feeds/feeds_snapshot_handoff_5282_test.go` | reconfiguration handoff | negative | Removed feeds drop, failed reconfiguration retains data, and success replaces it. |
| `pkg/feeds/feeds_test.go` | parser and stale policy | negative | CIDR canonicalization, malformed-line degradation, content hash, hold interval, and cold-start behavior are covered. |

### Flow export

Dimensions checked: big-endian template/header/data encodings and length formulas; source/ODID identity and HA symmetry; IPv4/IPv6/NAT/biflow field consistency; bounded batch/collector backpressure; lock/atomic handoff and route-mask cache behavior; collector/version/template isolation. Existing tests pin template-record congruence, payload limits, batch caps, source binds, reconfiguration handoff, and sequence semantics. The probabilistic 32-bit identity collision concern was refuted as the documented, pre-existing stable-ID design, not retained as a new finding.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/flowexport/addr_format_test.go` | collector addressing | negative | IPv6 destinations and source binds are bracketed and resolvable. |
| `pkg/flowexport/collector_health_test.go` | collector telemetry | negative | Failure state, timestamps, and transition callbacks are edge-correct. |
| `pkg/flowexport/collector_stall_4423_test.go` | collector backpressure | negative | Dead collectors are deadline-bounded, backed off, and cannot indefinitely stall peers. |
| `pkg/flowexport/cos_fields_test.go` | CoS wire fields | negative | NetFlow and IPFIX encode real TOS, flags, and interface attribution. |
| `pkg/flowexport/dropped_fields_test.go` | template compatibility | negative | Unsupported fields are absent from both templates and records. |
| `pkg/flowexport/exporter_id_3740_test.go` | exporter identity | negative | Per-group SourceID/ODID values are stable, nonzero, and HA-symmetric. |
| `pkg/flowexport/exporter_test.go` | exporter construction/wire | negative | Sampling, template composition, source selection, and base IPFIX/V9 encodings are covered. |
| `pkg/flowexport/exporterid.go` | stable identity | negative | Config-derived FNV ID is nonzero and protocol-scoped without node-local input. |
| `pkg/flowexport/flowbatch_bounded_test.go` | pending queue | negative | Per-family caps, drop accounting, high-water depth, and concurrent add/drain are bounded. |
| `pkg/flowexport/flowdir_test.go` | flow direction extension | negative | Direction is opt-in and record/template widths remain aligned. |
| `pkg/flowexport/flowstart_test.go` | flow timing | negative | Real creation timestamp wins; fallback and future-created values are bounded. |
| `pkg/flowexport/handoff_lease_4963_test.go` | exporter retirement | negative | Retire waits for admitted adds and counts post-retire handoff rejects. |
| `pkg/flowexport/ingress_interface_test.go` | interface attribution | negative | Ingress interface field is populated in both export formats. |
| `pkg/flowexport/instance_isolation_test.go` | sampling instances | negative | Counters and address-family ownership do not cross instances. |
| `pkg/flowexport/ipfix.go` | IPFIX encoder/exporter | negative | Templates, enterprise fields, record widths, sequence updates, batching, and close conversion agree. |
| `pkg/flowexport/ipfix_biflow_test.go` | IPFIX biflow fields | negative | Reverse counters use correct enterprise specifications and data order. |
| `pkg/flowexport/ipfix_sampler_test.go` | IPFIX options | negative | Systematic sampling options/template and sequence accounting are RFC-shaped. |
| `pkg/flowexport/ipfix_seqnum_test.go` | IPFIX sequencing | negative | Template and data messages preserve cumulative record-sequence semantics. |
| `pkg/flowexport/manager.go` | config resolution | negative | Per-instance/per-template grouping, version binding, deterministic ordering, and family scoping are preserved. |
| `pkg/flowexport/multigroup_wire_4422_test.go` | multi-group collision | negative | Groups sharing a collector remain separated by exporter identity. |
| `pkg/flowexport/netflow.go` | NetFlow v9 encoder/exporter | negative | FlowSet padding, payload chunking, uptime, and template/record widths are consistent. |
| `pkg/flowexport/netflow_multirecord_4896_test.go` | V9 multi-record framing | negative | Record packing and terminal FlowSet padding remain parseable. |
| `pkg/flowexport/per_collector_source_3745_test.go` | source address resolution | negative | Nested server source addresses override family and inline defaults per collector. |
| `pkg/flowexport/postnat_test.go` | post-NAT export | negative | Every record has a translated tuple, falling back to pre-NAT values when absent. |
| `pkg/flowexport/protocol_num_test.go` | protocol attribution | negative | Raw protocol number, including non-TCP/UDP values, reaches export. |
| `pkg/flowexport/routemask.go` | asynchronous FIB masks | negative | Cache key includes VRF scope, lookup is bounded/deduplicated, and cold misses are observable. |
| `pkg/flowexport/routemask_vrf_test.go` | route-mask VRF | negative | Ingress/egress fallback scopes both source and destination consistently. |
| `pkg/flowexport/srcmask_dstmask_test.go` | route-mask wire fields | negative | Default-route zero differs from unresolved zero through external telemetry. |
| `pkg/flowexport/template_group_test.go` | group resolution | negative | Undefined templates are skipped and default/single-template fallback is deterministic. |
| `pkg/flowexport/transport.go` | collectors and flow batch | negative | Dial cleanup, write deadlines/backoff, health locks, and capped add/drain queue are bounded. |
| `pkg/flowexport/transport_test.go` | collector transport | negative | Source errors and mid-loop failures close already-open connections. |
| `pkg/flowexport/version_binding_test.go` | version selection | negative | Each server selects exactly one configured export version. |

### Logging and event processing

Dimensions checked: raw wire-size/offset/endianness contracts; bounded event/subscriber queues and close synchronization; partial stream-frame recovery and reconnect bounds; syslog/local/trace file lifecycle; reentrancy and lock ordering; structured/binary/vSRX field parity. Raw decoding is guarded at the 144-byte baseline and the additive 152/160-byte fields are length gated. EventBuffer closes subscriptions safely under its fanout lock, and file writers bound observable loss. F002 remains because `slog.Handler` derivatives do not share client state across configuration replacement; no regression test exercises this lifecycle.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/logging/aggregator.go` | session aggregation | negative | Space-Saving top-K is lock-protected, cardinality-bounded, and final flush avoids double emission. |
| `pkg/logging/aggregator_flush_5313_test.go` | aggregator shutdown | negative | Cancel flushes pending aggregates exactly once and suppresses empty output. |
| `pkg/logging/aggregator_test.go` | aggregate accuracy | negative | Heavy-hitter, cap, reset, IPv6, and top-N behavior remain bounded. |
| `pkg/logging/binary_test.go` | binary/raw wire ABI | negative | Raw frame baseline/rejection, offsets, timestamps, close policy IDs, formats, and sink framing are pinned. |
| `pkg/logging/default_policy_sentinel_3057_test.go` | policy identity | negative | Default-policy sentinel is rendered consistently with the dataplane. |
| `pkg/logging/event_filter_args.go` | CLI event filtering | negative | Count, zone, protocol, and action parsing reject invalid argument combinations. |
| `pkg/logging/event_filter_args_test.go` | CLI event filtering | negative | Filter grammar and apply-state behavior are pinned. |
| `pkg/logging/event_severity_test.go` | severity mapping | negative | Permit screen alarms are notice rather than false error alarms. |
| `pkg/logging/event_time_test.go` | event timestamps | negative | Decision timestamps win and decode/live paths agree with safe fallback. |
| `pkg/logging/eventbuf.go` | event ring/subscribers | negative | Ring capacity, subscription cap, nonblocking fanout, and close ordering are synchronized. |
| `pkg/logging/eventbuf_close_3384_test.go` | subscription teardown | negative | Close is idempotent, closes the channel, and cannot race a fanout send. |
| `pkg/logging/eventbuf_negative_3342_test.go` | event ring bounds | negative | Negative count and zero capacity cannot panic. |
| `pkg/logging/eventbuf_subscriber_cap_4484_test.go` | subscriber admission | negative | Untrusted admission is capped while trusted subscriptions preserve contract. |
| `pkg/logging/eventbuf_zone0_3338_test.go` | filter semantics | negative | Zone zero is selectable rather than confused with no filter. |
| `pkg/logging/goid.go` | reentrancy identity | negative | Current goroutine parser is scoped to the syslog reentrancy guard. |
| `pkg/logging/host_inbound_deny_3610_test.go` | denial reason | negative | Host-inbound and policy-deny reasons remain distinct. |
| `pkg/logging/locallog.go` | local log writer | negative | Hardened open, mutexed rotation, write/rotation counters, and terminal close prevent silent loss. |
| `pkg/logging/locallog_format_3409_test.go` | local format parity | negative | standard, structured, binary, and sd-syslog paths select correct bodies. |
| `pkg/logging/locallog_test.go` | local writer resilience | negative | File modes, errors, rotation, and post-close behavior are observable. |
| `pkg/logging/per_policy_log_test.go` | event log gate | negative | Session open/close human-facing logs obey the per-policy gate while callbacks remain active. |
| `pkg/logging/protocol_num_builder_3382_test.go` | protocol source | negative | Builders retain authoritative numeric IP protocol. |
| `pkg/logging/protoname_test.go` | protocol naming | negative | Name lookup uses the shared protocol source of truth. |
| `pkg/logging/ringbuf.go` | event reader/raw decoder | negative | Wire reads are length-gated, little/big endian offsets match producer, callbacks precede gated sinks, and fanout snapshots avoid lock-held I/O. |
| `pkg/logging/rtflow_sessionid_4915_test.go` | session identity ABI | negative | Extended session IDs correlate open/close while legacy frames retain compatible fallback. |
| `pkg/logging/session_close_binary_slog_4914_test.go` | close sink parity | negative | Close policy/action fields agree across binary and slog paths. |
| `pkg/logging/session_close_format_test.go` | close formatting | negative | Close records omit fabricated forwarding action. |
| `pkg/logging/session_close_slog_policyid_4796_test.go` | close policy ID | negative | Slog resolves admitting policy from close extension. |
| `pkg/logging/session_create_format_test.go` | create formatting | negative | Session-create records omit fabricated forwarding action. |
| `pkg/logging/slog_handler.go` | default slog forwarding | A9-b1-F002 | All `WithAttrs`/`WithGroup` derivatives must observe the currently configured client set. |
| `pkg/logging/syslog.go` | syslog transport | negative | Client lock serializes close/reconnect/write; stream deadlines and partial-frame teardown prevent permanent desync. |
| `pkg/logging/syslog_close_resurrection_4806_test.go` | client terminal close | negative | Closed clients cannot reconnect or resurrect after replacement. |
| `pkg/logging/syslog_lazy_connect_3351_test.go` | stream startup | negative | TCP/TLS dial laziness and later recovery preserve configuration availability. |
| `pkg/logging/syslog_partial_frame_3874_test.go` | stream framing | negative | Partial writes close corrupt streams, clean timeout does not, and reentrancy remains live. |
| `pkg/logging/syslog_reentrancy_test.go` | slog recursion | negative | Same-goroutine recursion is suppressed while concurrent forwarding and no-client fast path remain correct. |
| `pkg/logging/syslog_replace_close_3579_test.go` | syslog replacement | negative | Event-reader replacement closes prior clients exactly once. |
| `pkg/logging/syslog_resilience_test.go` | stream resilience | negative | Write deadlines, cooldown, recovery, and health counters bound repeated failure. |
| `pkg/logging/syslog_test.go` | syslog formats/filtering | negative | Severity, facility, categories, UDP/TCP/TLS framing, and defaults are covered. |
| `pkg/logging/trace.go` | trace writer | negative | Sanitized names, hardened files, filters, rotation, and visible write loss protect audit output. |
| `pkg/logging/trace_filter_3422_test.go` | trace filters | negative | Invalid/empty filters fail closed and protocol matching is exact. |
| `pkg/logging/trace_size_3424_test.go` | trace rotation bounds | negative | File count/size clamps prevent pathological rotation. |
| `pkg/logging/trace_test.go` | trace file safety | negative | Traversal/symlink/nonregular files fail, modes tighten, and rotation errors remain observable. |

### RPM

Dimensions checked: probe transition semantics and pin hold-state behavior; ICMP packet/reply matching and VRF bind setup; DNS and HTTP context/lifetime behavior; result/callback locking; link-local scope and source binding; deterministic display. ICMP and TCP/HTTP setup errors are classified as environment failures that hold state rather than actuating routes. HTTP disables per-probe keep-alives and closes idle connections. No surviving issue; a possible buffered-event replay ordering interleaving was refuted as an unproven ordering-only test gap, not a demonstrated control or state breach.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/rpm/display.go` | configured RPM display | negative | Probe/test map keys render in deterministic sorted order with effective defaults. |
| `pkg/rpm/event_buffer_3755_test.go` | event callback bootstrap | negative | Pre-registration events are bounded, FIFO-replayed, and later events are live. |
| `pkg/rpm/http_scheme_2495_test.go` | HTTP target parsing | negative | Schemeless names receive HTTP and unsupported schemes fail before probing. |
| `pkg/rpm/http_transport_leak_4912_test.go` | HTTP connection lifecycle | negative | Bodyless responses do not strand per-probe connections. |
| `pkg/rpm/icmp.go` | ICMP/DNS probe path | negative | Echo ID/seq/peer matching, context deadline, VRF bind, link-local zone, and setup-error classification are bounded. |
| `pkg/rpm/icmp_ctx_2647_test.go` | resolver context | negative | Hostname lookup honors cancel/deadline while literal IP bypasses DNS. |
| `pkg/rpm/icmp_linklocal_2494_test.go` | IPv6 scope | negative | Explicit/default zones work and unscoped link-local targets hold state. |
| `pkg/rpm/icmp_test.go` | ICMP behavior | negative | Valid replies, foreign packets, timeout, socket options, and transition setup errors are covered. |
| `pkg/rpm/pin_hold_test.go` | next-hop pin gating | negative | Failed/unassigned/reprogramming pin paths send no probe and hold state. |
| `pkg/rpm/probe_dialer_2492_test.go` | TCP/HTTP source bind | negative | Malformed source is setup failure; empty/default and valid source behavior are distinct. |
| `pkg/rpm/resolver_setup_5061_test.go` | scoped resolver setup | negative | Resolver bind failure is reclassified as setup failure for all probe types. |
| `pkg/rpm/rpm.go` | RPM manager | negative | Stop/reapply waits probes; result updates are locked; cycle transitions are at most once and setup errors hold state. |
| `pkg/rpm/scoped_hostname_2493_test.go` | scoped hostname | negative | Scoped DNS uses matching resolver path and literals avoid DNS. |
| `pkg/rpm/transition_cycle_test.go` | transition state machine | negative | Threshold, recovery, one-probe, and cross-cycle loss semantics emit one transition per cycle. |

### A9-b2: Observability, telemetry and event processing (23 files)

Batch-list SHA-256: `8a9caf9f14ea0680a20735da20fd80ac7de04b142fa9c0f9b0b52437114369aa`.

### Agent, BER, request processing, and interface MIB

- Correctness/security/fail-open: community source restrictions, SET authorization, response-size bounds, GETBULK ordering, BER bounds, and engineBoots fail-closed behavior were traced. Surviving issues are error erasure at the interface callback, cross-generation authorization/data reads, non-unique engine identity input, permissive partial-varbind decode, the wrong unknown-object exception, and single-octet encoding of a multi-octet first OID subidentifier. The known GETBULK amplification/sizing root cause was suppressed as a prior finding.
- Memory safety/concurrency/truncation/leaks: no unsafe code or raw pointers exist here; BER slices are bounds-checked before indexing. The race suite passes, but `cfgMu` prevents data races without making one PDU generation-consistent. UDP input is bounded to 4096 bytes. Lifecycle leaks already tracked by #4916 were not re-reported.
- vSRX completeness: basic system, ifTable, ifXTable, v2c source authorization, and read-only SET behavior exist. Exception semantics still diverge from a standards-compliant Junos-style agent.
- Performance/latency: one lazy netlink snapshot per PDU and O(log n) response trimming are positive. `cfgMu` is acquired per system varbind, and candidate GETBULK pre-expansion was duplicate-suppressed against `codex-review-175.md`.
- Modularity/tests: the callback cannot return an error, and hand-written BER combines validation and permissive recovery. Tests are broad on happy paths and recent regressions, but omit callback errors, malformed mixed varbinds, OIDs rooted at 2.x, and synchronized config-update interleavings. The interface-order candidate was refuted against Linux's ascending ifIndex dump iterator.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/snmp/agent.go` | Agent lifecycle, v2c PDUs, BER, MIB walk | A9-b2-F005, A9-b2-F006, A9-b2-F007, A9-b2-F009, A9-b2-F010, A9-b2-F012 | One immutable authorization/data generation per PDU; collection failures stay distinguishable; EngineID is unique; malformed BER fails closed; exception and OID encoding preserve wire semantics. |
| `pkg/snmp/agent_clients_4289_test.go` | v2c source ACL tests | negative | Allowed, denied, and longest-prefix `restrict` sources exercise the live source-IP gate; no surviving new issue. |
| `pkg/snmp/agent_secret_log_4302_test.go` | secret-safe logging tests | negative | Unknown/denied communities are not rendered into debug logs; no surviving new issue. |
| `pkg/snmp/agent_set_test.go` | v2c SET and live config tests | A9-b2-F006 | Sequential downgrade/delete and race-freedom are covered, but no test synchronizes a request between old authorization and new MIB data. |
| `pkg/snmp/agent_stop_leak_4916_test.go` | lifecycle shutdown tests | negative | Watcher cancellation, backlog abandonment, idempotence, and worker join were checked; the broader Stop root is already tracked and was duplicate-suppressed. |
| `pkg/snmp/agent_test.go` | BER, system MIB, ifTable/ifXTable, USM helpers | A9-b2-F007, A9-b2-F012 | Tests derive identity only from hostname and cover only 1.3-rooted OIDs; these assumptions miss the surviving invariants. |
| `pkg/snmp/ber_timeticks_4924_test.go` | TimeTicks BER regression | negative | Unsigned high-bit values receive a leading zero and long-uptime encoding stays canonical. |
| `pkg/snmp/engineid_4917_test.go` | EngineID length/determinism tests | A9-b2-F007 | Length and distinct-hostname hashing are covered, but administrative uniqueness across appliances sharing one hostname is not. |
| `pkg/snmp/getbulk_order_5065_test.go` | GETBULK ordering tests | negative | Repetition-major order and exhausted columns are covered; Linux's dump iterator supplies ascending ifIndex order to the production callback. |
| `pkg/snmp/getbulk_size_test.go` | GETBULK sizing/snapshot tests | negative | Size floors/caps, binary trimming, and one LinkList call per PDU hold; the remaining expansion-cost candidate is an exact prior duplicate. |
| `pkg/snmp/getresp_size_4918_test.go` | GET/GETNEXT size tests | negative | Oversized fixed-cardinality responses become `tooBig`; no distinct non-duplicate issue survived. |

### Trap construction and delivery

- Correctness/security/fail-open: packet shape and v1/v2 selection are sound, but trap-group identity and categories are not enforced, and queued jobs remain authorized by stale config. These can lose or misroute operational notifications.
- Memory safety/concurrency/truncation/leaks: the queue is bounded and the drop counter is atomic; Stop joins the worker. A global serial worker couples all destinations, while live `UpdateConfig` has no queue generation or invalidation barrier.
- vSRX completeness: Junos uses the trap-group name as the v1/v2c community and applies per-group category filters. Both accepted semantics are absent at emission time, so both findings carry `vsrx-parity`.
- Performance/latency: link-monitor callers are asynchronous, which is positive. One two-second DNS/dial stall can nevertheless block all targets, and large fanout shares one 256-job queue.
- Modularity/tests: per-Agent sender injection is a good seam. Tests prove producer non-blocking and single-target delivery, but not target isolation, config rotation, category filtering, or the Junos community contract.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/snmp/traps.go` | v1/v2 trap framing, target selection, async queue | A9-b2-F001, A9-b2-F002, A9-b2-F003, A9-b2-F004 | Each group carries its own wire identity/filter, one target cannot starve another, and queued work remains valid under the current config generation. |
| `pkg/snmp/traps_async_2991_test.go` | async/backpressure tests | A9-b2-F003 | Producer non-blocking and queue capacity are covered, but a slow target followed by a healthy target is not. |
| `pkg/snmp/traps_community_2989_test.go` | community selection tests | A9-b2-F001 | The test pins deterministic lexicographic query-community selection, which conflicts with the Junos trap-group-name wire contract. |
| `pkg/snmp/traps_test.go` | v2 trap shape/delivery tests | A9-b2-F001, A9-b2-F002 | Packet shape is covered using an injected community; no test drives group identity or categories from config. |
| `pkg/snmp/traps_version_3948_test.go` | v1/v2/all selection tests | negative | Version-specific PDU shape and `all` fanout are correct; no distinct issue survived. |

### SNMPv3 USM, privacy, context, and reports

- Correctness/security/fail-open: HMAC field location, per-user minimum security level, timeliness, engineBoots persistence, AES request IV construction, and non-default context-name empty views are robust. The authoritative EngineID is discarded, and USM report counters are hard-coded to zero.
- Memory safety/concurrency/truncation/leaks: no unsafe blocks exist. Crypto buffers are length-checked and packet size is bounded. Go's `crypto/rand.Read` contract always fills or terminates, refuting the ignored-error candidate; random salt collision alone was not retained as a concrete bug.
- vSRX completeness: authNoPriv/authPriv request handling exists for a limited USM surface. VACM, full context-engine dispatch, and v3 notification framework are not represented by accepted runtime config in this batch; no speculative finding was padded from absence alone.
- Performance/latency: password localization is configuration-time; request HMAC/encryption runs on the single serving goroutine. No extra hot-path finding survived beyond the duplicate GETBULK cost.
- Modularity/tests: positional auth-field parsing is well tested. Missing negative tests use a valid local key with a mismatched authoritative/context EngineID and assert the actual USM counter value.

| Path | Module/subsystem | Result | Invariant checked |
|---|---|---|---|
| `pkg/snmp/v3.go` | USM parse/auth/privacy/context/report path | A9-b2-F006, A9-b2-F008, A9-b2-F011 | Authentication identity must match the local authoritative engine; one response uses one config generation; USM counters reflect actual events. |
| `pkg/snmp/v3_auth_test.go` | HMAC locator/auth tests | A9-b2-F008 | Field-position and long-form BER cases pass, but all tests make the packet EngineID and selected key identity agree. |
| `pkg/snmp/v3_context_test.go` | scoped context tests | A9-b2-F008 | Context-name gating is covered; a mismatched `contextEngineID` is not. |
| `pkg/snmp/v3_priv_iv_test.go` | AES privacy IV tests | negative | Received boots/time drive decryption and response encryption round-trips; no surviving distinct privacy bug. |
| `pkg/snmp/v3_seclevel_test.go` | USM security-level tests | negative | noAuthPriv and per-user downgrade bypasses fail closed; this prior security root is fixed and not re-reported. |
| `pkg/snmp/v3_set_test.go` | authenticated v3 SET test | negative | Authenticated SET reaches the handler and returns `notWritable`; no writable MIB exists. |
| `pkg/snmp/v3_timeliness_test.go` | replay window/boots/report tests | A9-b2-F011 | Window, boots persistence, and report OID are covered, but report counter values are never checked or incremented. |

### A10-b1: Services, CLI, build/deploy tooling and unmatched modules (61 files)

Batch-list SHA-256: `e92a0bd68d5009860fb9b89b6884b392cc7b662de287b44cc17003a3f979e6b4`.

Legend for every module row: `C/S/F` = correctness, security, and fail-open;
`M/C/T/L` = memory safety, concurrency, truncation, and leaks; `P` = vSRX
feature/runtime relevance; `Perf` = latency/resource behavior; `Mod/Test` =
modularity and test coverage. `negative` means no non-duplicate finding survived.

### Legacy BPF header ABI

The assigned `bpf/` tree contains headers only at this commit; `rg --files bpf`
found no translation units or active caller. I reviewed the layout, bounded parser,
checksum, map, HA, filter, and tracing invariants as legacy compatibility code,
not as the Rust userspace forwarding path.

| Path | Result | Invariant checked |
|---|---|---|
| `bpf/headers/xpf_common.h` | negative | C/S/F: byte order, packet metadata, zone/HA flags; M/C/T/L: fixed-width ABI; P: legacy-only; Perf: per-CPU scratch layout; Mod/Test: shared layout documentation. |
| `bpf/headers/xpf_conntrack.h` | negative | C/S/F: canonical reverse tuples and TCP-state timeout selection; M/C/T/L: fixed 16-byte copies; P: no active caller; Perf: inline bounded helpers; Mod/Test: ABI-local. |
| `bpf/headers/xpf_helpers.h` | negative | C/S/F: Ethernet/IP/L4 bounds, checksum, filter, fabric and watchdog fail-closed paths; M/C/T/L: verifier bounds and per-CPU maps; P: legacy-only; Perf: bounded loops/no allocations; Mod/Test: no in-tree callers. |
| `bpf/headers/xpf_maps.h` | negative | C/S/F: map key/value types and policy/NAT/HA ownership; M/C/T/L: per-CPU vs shared map choice; P: legacy-only; Perf: bounded maps and no-prealloc sparse keys; Mod/Test: generated-ABI note present. |
| `bpf/headers/xpf_nat.h` | negative | C/S/F: IPv4/IPv6/embedded-ICMP rewrite checksum order; M/C/T/L: packet bounds before writes; P: legacy-only; Perf: inline fixed work; Mod/Test: no translation-unit caller. |
| `bpf/headers/xpf_trace.h` | negative | C/S/F: tracing compile-time disabled; M/C/T/L: no packet mutation; P: legacy-only; Perf: no production printk; Mod/Test: macro no-op contract. |

### Remote CLI command and display paths

| Path | Result | Invariant checked |
|---|---|---|
| `cmd/cli/clear.go` | negative | C/S/F: strict session selectors and destructive clear RPC routing; M/C/T/L: bounded ports; P: control-plane parity; Perf: cold path; Mod/Test: error propagation. |
| `cmd/cli/commit_rollback_4868_test.go` | negative | C/S/F: confirmed-commit timeout and unknown modifier rejection; M/C/T/L: narrowing boundaries; P/Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/completion_pos_4970_test.go` | negative | C/S/F: rune/byte completion cursor agreement; M/C/T/L: no invalid byte slicing; P/Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/grpc_maxrecv_5321_test.go` | negative | C/S/F: configuration receive cap preserves store maximum; M/C/T/L: bounded framing headroom; P/Perf: control path; Mod/Test: dial-option coverage present. |
| `cmd/cli/main.go` | negative | C/S/F: commit, config load, diagnostics and policy-query argument handling; M/C/T/L: RPC deadlines and config load behavior; P: remote parity; Perf: bounded gRPC cap; Mod/Test: covered by focused tests. |
| `cmd/cli/main_test.go` | negative | C/S/F: remote CLI construction behavior; M/C/T/L: N/A; P/Perf: N/A; Mod/Test: base harness coverage. |
| `cmd/cli/monitor.go` | negative | C/S/F: monitor stream cancellation and selector behavior; M/C/T/L: reader lifecycle, cloned protobuf and bounded frame channel; P: remote monitoring parity; Perf: bounded buffering; Mod/Test: focused key-reader tests. |
| `cmd/cli/monitor_keyreader_4694_test.go` | negative | C/S/F: monitor reader exits before terminal restoration; M/C/T/L: no stdin-reader leak; P/Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/nontty_test.go` | negative | C/S/F: non-TTY confirmation/configure rejection; M/C/T/L: no stranded config lock; P/Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/pipe_filter_case_4968_test.go` | negative | C/S/F: case-sensitive output-filter semantics; M/C/T/L: N/A; P: local/remote parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/policymatch_dup_3709_test.go` | negative | C/S/F: delimiter-unsafe zone names fail closed; M/C/T/L: N/A; P: policy-query parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/query_strictness_3696_test.go` | negative | C/S/F: malformed policy selectors cannot widen a query; M/C/T/L: typed parsing; P: policy-query parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/request.go` | negative | C/S/F: confirmation and userspace-control command parsing; M/C/T/L: parser indexes guarded by shared parsers; P: HA/control parity; Perf: cold path; Mod/Test: WireGuard coverage. The failover arity candidate is a corpus duplicate. |
| `cmd/cli/request_wireguard_test.go` | negative | C/S/F: local WireGuard generation requires no daemon RPC; M/C/T/L: key generation errors surfaced; P: feature parity; Perf: no contended control socket; Mod/Test: regression coverage present. |
| `cmd/cli/rollback_3447_test.go` | negative | C/S/F: invalid rollback token never becomes rollback 0; M/C/T/L: int32 bounds; P: config safety; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/shared.go` | negative | C/S/F: dispatch, config mode, filters, rollback and completion fail loud; M/C/T/L: cancellation and bounded tail; P: local parity; Perf: pipe-buffer candidate is a corpus duplicate; Mod/Test: focused tests. |
| `cmd/cli/show.go` | negative | C/S/F: show-topic routing and format selection; M/C/T/L: RPC errors surfaced; P: remote display parity; Perf: cold path; Mod/Test: split-module boundaries clear. |
| `cmd/cli/show_bgp_firewall_effective_4967_test.go` | negative | C/S/F: advertised BGP/firewall-effective commands reach the intended topics; M/C/T/L: N/A; P: parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_dhcp.go` | negative | C/S/F: DHCP inventory RPC errors surfaced; M/C/T/L: N/A; P: display parity; Perf: cold path; Mod/Test: narrow wrappers. |
| `cmd/cli/show_events_zone_3547_test.go` | negative | C/S/F: event zone selector is forwarded intact; M/C/T/L: N/A; P: log-query parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_firewall_effective.go` | negative | C/S/F: filter/family extraction mirrors dispatcher; M/C/T/L: N/A; P: display parity; Perf: cold path; Mod/Test: covered by effective-show tests. |
| `cmd/cli/show_flow.go` | A10-b1-F001 | C/S/F: strict session filters; M/C/T/L: `limit` narrows an unbounded host `int` into `int32`; P: session inspection parity; Perf: server cap; Mod/Test: missing overflow boundary. |
| `cmd/cli/show_flow_summary_5320_5323_test.go` | negative | C/S/F: peer-unreachable and dynamic-capacity rendering; M/C/T/L: N/A; P: HA observability parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_flowsession_3439_test.go` | A10-b1-F001 | C/S/F: strict session selector grammar; M/C/T/L: no test for `limit > MaxInt32`; P: flow display parity; Perf: N/A; Mod/Test: add the overflow boundary. |
| `cmd/cli/show_interfaces.go` | negative | C/S/F: interface statistics RPC error propagation; M/C/T/L: N/A; P: display parity; Perf: cold path; Mod/Test: narrow wrapper. |
| `cmd/cli/show_matchpolicies_port_3354_test.go` | negative | C/S/F: destination-port is retained in typed policy match; M/C/T/L: bounded port values; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_matchpolicies_test.go` | negative | C/S/F: match-policy presentation follows server verdict; M/C/T/L: N/A; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_nat.go` | negative | C/S/F: NAT display RPC failures mostly surface; M/C/T/L: no packet/runtime state ownership; P: NAT observability parity; Perf: cold path; Mod/Test: named-pool hit attribution candidate is a corpus duplicate. |
| `cmd/cli/show_policies_metadata_3672_test.go` | negative | C/S/F: policy inversion/log/schedule/count metadata is rendered; M/C/T/L: N/A; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_policies_scoped_global_3357_test.go` | negative | C/S/F: scoped globals are filtered per rule; M/C/T/L: N/A; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_protocols.go` | negative | C/S/F: protocol display dispatch; M/C/T/L: N/A; P: display parity; Perf: cold path; Mod/Test: narrow wrappers. |
| `cmd/cli/show_security.go` | A10-b1-F002 | C/S/F: secondary detail RPC error is silently converted into success; M/C/T/L: N/A; P: security observability parity; Perf: cold path; Mod/Test: no failure-path test. |
| `cmd/cli/show_security_selector_4908_test.go` | negative | C/S/F: dangling policy-zone selectors fail closed; M/C/T/L: N/A; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_services.go` | negative | C/S/F: service inventory topic routing; M/C/T/L: N/A; P: display parity; Perf: cold path; Mod/Test: narrow wrapper. |
| `cmd/cli/show_system.go` | negative | C/S/F: history/rollback show routing; M/C/T/L: display-only int conversion candidate is suppressed as the known rollback narrowing root cause; P: display parity; Perf: cold path; Mod/Test: no new surviving gap. |
| `cmd/cli/show_wireguard_test.go` | negative | C/S/F: WireGuard display topics; M/C/T/L: N/A; P: feature parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_zones_hostinbound_3654_test.go` | negative | C/S/F: host-inbound presentation reflects shared view; M/C/T/L: N/A; P: security parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_zones_polerr_3669_test.go` | negative | C/S/F: policy inventory failures surface after partial zone output; M/C/T/L: N/A; P: security observability parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/show_zones_tiers_3683_test.go` | negative | C/S/F: zone-pair/global/default tiers are distinct; M/C/T/L: N/A; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/testpolicy_port_test.go` | negative | C/S/F: invalid destination ports do not widen policy tests; M/C/T/L: bounds checked; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/testpolicy_protocol_test.go` | negative | C/S/F: invalid protocol does not become wildcard; M/C/T/L: typed validation; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/testpolicy_srcport_test.go` | negative | C/S/F: invalid source ports do not widen policy tests; M/C/T/L: bounds checked; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/cli/usage_matchpolicies_3628_test.go` | negative | C/S/F: documented selector set matches parser; M/C/T/L: N/A; P: policy parity; Perf: N/A; Mod/Test: regression coverage present. |

### Daemon, shim verifier, and upgrade tooling

| Path | Result | Invariant checked |
|---|---|---|
| `cmd/shimverify/main.go` | negative | C/S/F: verifier reject has distinct non-success exit; M/C/T/L: no production attachment; P: userspace shim gate; Perf: build/deploy cold path; Mod/Test: thin wrapper. |
| `cmd/xpfd/leftover_args_5322_test.go` | negative | C/S/F: privileged lifecycle verbs reject leftovers; M/C/T/L: N/A; P: upgrade safety; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/xpfd/main.go` | negative | C/S/F: command dispatch, strict check-config, verifier and daemon initialization fail closed; M/C/T/L: bounded config input; P: userspace dataplane gate; Perf: cold-path sampling guarded; Mod/Test: focused parser tests. The check-config TOCTOU candidate is a corpus duplicate. |
| `cmd/xpfd/publish_generation.go` | negative | C/S/F: lock serialization and unreadable-journal GC skip; M/C/T/L: durable journal guard; P: upgrade generation coherence; Perf: cold path; Mod/Test: regression coverage present. |
| `cmd/xpfd/publish_generation_gc_4876_test.go` | negative | C/S/F: malformed journal suppresses destructive GC; M/C/T/L: N/A; P: upgrade recovery; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/xpfd/seed_runtime.go` | negative | C/S/F: first-install seeding and leftover rejection; M/C/T/L: N/A; P: rollback-target availability; Perf: cold path; Mod/Test: regression coverage present. |
| `cmd/xpfd/upgrade.go` | negative | C/S/F: rolling/standalone gating and helper health fail-closed; M/C/T/L: no shared-state races in seams under production use; P: HA continuity; Perf: bounded health deadline; Mod/Test: focused coverage. |
| `cmd/xpfd/upgrade_args_4869_test.go` | negative | C/S/F: positional `rolling` typo cannot select standalone cut; M/C/T/L: N/A; P: HA safety; Perf: N/A; Mod/Test: regression coverage present. |
| `cmd/xpfd/upgrade_helper_health_5286_test.go` | negative | C/S/F: helper must be armed, forwarding, and target-versioned; M/C/T/L: N/A; P: userspace dataplane readiness; Perf: bounded probe; Mod/Test: production wiring covered. |
| `cmd/xpfd/upgrade_kernel.go` | negative | C/S/F: kernel lifecycle arity, lock and drain/rejoin checks; M/C/T/L: deferred lock release; P: HA/no-dual-primary sequencing; Perf: cold path; Mod/Test: parser coverage present. |

### Evidence-only C probes

| Path | Result | Invariant checked |
|---|---|---|
| `docs/pr/812-tx-latency-histogram/evidence/vdso_probe.c` | negative | C/S/F: diagnostic probe only; M/C/T/L: bounded local variables; P: non-runtime evidence; Perf: measurement helper; Mod/Test: documentation artifact. |
| `docs/pr/812-tx-latency-histogram/evidence/vdso_probe2.c` | negative | C/S/F: diagnostic probe only; M/C/T/L: bounded local variables; P: non-runtime evidence; Perf: measurement helper; Mod/Test: documentation artifact. |

### A10-b2: Services, CLI, build/deploy tooling and unmatched modules (120 files)

Batch-list SHA-256: `2978ab239b02de47b85cfbd443f86f3eff5c931af1fd9dd84b00293390f48552`.

Every row was inspected from the detached base. `negative` means no credible non-duplicate finding survived. For every module, correctness/security/fail-open behavior, memory/concurrency/truncation/leaks, vSRX completeness where relevant, latency, modularity, and test gaps were checked.


### Core CLI and apply

Commit/rollback, redaction, config parsing, cancellation, pipe/pager bounds, and stable syslog zone ID publication were sound. The global stdout redirect has one interactive dispatcher and no demonstrated concurrent command trace.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/cli/app_resolve.go | resolution | negative | invalid app values do not change forwarding |
| pkg/cli/apply.go | standalone apply | negative | stable zone IDs and compiled config preserved |
| pkg/cli/apply_syslog_zonemap_3704_test.go | apply test | negative | collision survivor mapping |
| pkg/cli/chrony.go | NTP display | negative | malformed fields ignored |
| pkg/cli/cli.go | lifecycle | negative | cancel slots isolated |
| pkg/cli/cli_activate_test.go | config test | negative | edit-relative activation |
| pkg/cli/cli_clear.go | session clear | negative | reverse/NAT keys and partial error honesty |
| pkg/cli/cli_clear_errors_test.go | clear test | negative | iterator/delete failures visible |
| pkg/cli/cli_clear_reversekey_test.go | clear test | negative | translated reverse key deleted |
| pkg/cli/cli_commit_4868_test.go | commit test | negative | invalid modifier rejected |
| pkg/cli/cli_commit_confirm_pending_4000_test.go | commit test | negative | confirm-window edits retained |
| pkg/cli/cli_commit_test.go | commit test | negative | daemon callback preferred |
| pkg/cli/cli_config.go | config command | negative | commit bounds and redact paths |
| pkg/cli/cli_config_test.go | config test | negative | load/copy/rename contract |
| pkg/cli/cli_dispatch.go | dispatch | negative | ordinary pipe/pager output streams boundedly |
| pkg/cli/cli_dispatch_pager_stream_4709_test.go | pager test | negative | incremental producer consumption |
| pkg/cli/cli_dispatch_pipe_stream_4731_test.go | pipe test | negative | no whole-output filter buffer |
| pkg/cli/cli_display_fidelity_4908_test.go | display test | negative | local/peer fidelity |
| pkg/cli/cli_helpers.go | helper | negative | absent runtime state safe |
| pkg/cli/cli_last_cap_5037_test.go | pipe test | negative | tail operand cap |
| pkg/cli/cli_matchpolicies_scheduler_3414_test.go | policy test | negative | absent scheduler fail-closed |

### Requests, HA, and RBAC

Argv construction uses separators; HA/peer paths have explicit timeout/auth; maintenance prompts are RBAC-gated. `clear system config-lock` was suppressed as the #4484 non-owner force-clear root-cause duplicate.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/cli/cli_request.go | request dispatch | negative | family routing |
| pkg/cli/cli_request_argv_test.go | argv test | negative | VRF/`--` separator |
| pkg/cli/cli_request_chassis.go | HA control | negative | RG/peer action handling |
| pkg/cli/cli_request_ping.go | diagnostic argv | negative | no option injection |
| pkg/cli/cli_request_policies_check.go | policy lint | negative | conservative superset only |
| pkg/cli/cli_request_policies_check_test.go | policy lint test | negative | exclusions/schedulers safe |
| pkg/cli/cli_request_security.go | security request | negative | IPsec/keygen guarded |
| pkg/cli/cli_request_system.go | system request | negative | confirmation and maintenance gate |
| pkg/cli/cli_request_testcmd.go | simulator | negative | parse failure cannot widen query |
| pkg/cli/cli_request_wireguard_test.go | WG test | negative | keypair contract |
| pkg/cli/cli_rollback_3447_test.go | rollback test | negative | malformed index rejected |
| pkg/cli/cluster_failover_test.go | HA test | negative | failover wiring |
| pkg/cli/peer.go | fabric gRPC | negative | auth, VRF, fallback, timeout |
| pkg/cli/peer_fabric_auth_5324_test.go | peer test | negative | rotating peer credential |
| pkg/cli/permissions.go | RBAC | negative | prefix-resolved destructive gates |
| pkg/cli/permissions_custom_class_4304_test.go | RBAC test | negative | no custom-class overgrant |
| pkg/cli/permissions_dataplane_maint_4859_test.go | RBAC test | negative | userspace destructive verbs maintenance-only |
| pkg/cli/permissions_maintenance_4108_test.go | RBAC test | negative | system/failover maintenance-only |
| pkg/cli/permissions_monitor_traffic_4067_test.go | RBAC test | negative | capture requires control |
| pkg/cli/policymatch_dup_3709_test.go | matcher test | negative | duplicate suppression |


### Flow, NAT, and interfaces

Tuple display/endian handling, session iterator errors, NAT reverse entries, reth mapping, nil config values, and counter degradation were checked. The only surviving resource findings are the two flow display rows marked below.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/cli/cli_show_flow.go | flow session display | A10-b2-F001, A10-b2-F002 | bounded top-N and streaming brief output |
| pkg/cli/cli_show_flow_summary_5323_test.go | flow test | negative | dynamic maximum-session display |
| pkg/cli/cli_show_flow_test.go | flow test | negative | endpoint format; lacks high-volume flush test |
| pkg/cli/cli_show_interfaces.go | interface display | negative | zone/reth/unit kernel mapping |
| pkg/cli/cli_show_interfaces_detail.go | interface detail | negative | link/reth absence safe |
| pkg/cli/cli_show_interfaces_extensive.go | interface extensive | negative | bounded link inventory |
| pkg/cli/cli_show_interfaces_reth_4328_test.go | reth test | negative | bondless member display |
| pkg/cli/cli_show_interfaces_shared.go | interface helper | negative | DHCP/netlink failure safe |
| pkg/cli/cli_show_interfaces_stats.go | interface stats | negative | nil zone/counter error handling |
| pkg/cli/cli_show_interfaces_terse.go | terse display | negative | sorted/deduplicated peer/reth units |
| pkg/cli/cli_show_logical_unit_5325_test.go | unit test | negative | base interface resolution |
| pkg/cli/cli_show_nat.go | NAT display | negative | iterator errors visible, no mutation |
| pkg/cli/cli_show_nat_shared_test.go | NAT test | negative | shared renderer parity |
| pkg/cli/cli_show_nat_test.go | NAT test | negative | NAT view guards |
| pkg/cli/link.go | link helper | negative | sysfs failure display-only |

### Security presenters

Policy/scheduler parity, counter error reporting, nil HA-sync values, screen inventory, IPsec/WireGuard availability, and event selector fail-closed behavior were checked. No surviving fail-open or vSRX-parity finding was found.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/cli/cli_show_security.go | policy view | negative | runtime IDs/scopes/scheduler state |
| pkg/cli/cli_show_security_dispatch.go | security dispatch | negative | guarded zone/filter routing |
| pkg/cli/cli_show_security_filters.go | firewall view | negative | compiled term expansion/counters |
| pkg/cli/cli_show_security_flat_zone_local_3358_test.go | policy test | negative | no synthetic local name leak |
| pkg/cli/cli_show_security_ipsec.go | IPsec/IKE view | negative | unavailable status explicit |
| pkg/cli/cli_show_security_log.go | event view | negative | bounded history and strict selector parse |
| pkg/cli/cli_show_security_log_argparse_3347_test.go | log test | negative | missing/unknown selector fails |
| pkg/cli/cli_show_security_log_historical_zone_3335_test.go | log test | negative | event-time zone retained |
| pkg/cli/cli_show_security_log_negative_3342_test.go | log test | negative | invalid count avoids panic |
| pkg/cli/cli_show_security_nil_3476_test.go | nil test | negative | nil policy/zone/profile safe |
| pkg/cli/cli_show_security_objects.go | object view | negative | display-only address/app resolution |
| pkg/cli/cli_show_security_policy_addr_excluded_3336_test.go | policy test | negative | exclusion rendered |
| pkg/cli/cli_show_security_policy_index_3063_test.go | policy test | negative | multi-app index parity |
| pkg/cli/cli_show_security_scoped_global_3286_test.go | policy test | negative | scoped-global zones |
| pkg/cli/cli_show_security_scoped_global_3357_test.go | policy test | negative | selector scope |
| pkg/cli/cli_show_security_screen.go | screen view | negative | unavailable counters not zero |
| pkg/cli/cli_show_security_screen_inventory_3327_test.go | screen test | negative | full check inventory |
| pkg/cli/cli_show_security_test.go | security test | negative | screen/policy counter gates |
| pkg/cli/cli_show_security_wireguard.go | WG telemetry | negative | userspace-only status explicit |
| pkg/cli/cli_show_security_wireguard_test.go | WG test | negative | key/status formatting |
| pkg/cli/cli_show_security_zone_local_3358_test.go | zone-local test | negative | canonical local address display |
| pkg/cli/cli_show_security_zones.go | zone view | negative | host-inbound/counter errors visible |
| pkg/cli/cli_show_security_zones_explicit_any_3680_test.go | zone test | negative | explicit-any contract |
| pkg/cli/cli_show_security_zones_metadata_3684_test.go | zone test | negative | runtime metadata inventory |
| pkg/cli/cli_show_security_zones_policy_tiers_3658_test.go | zone test | negative | zone/global/default tiers |
| pkg/cli/host_inbound_display_3654_test.go | host-inbound test | negative | override/default-deny visible |


### Chassis, routing, services, system, completion

Chassis/peer status, routing presentation, effective filters, redaction, completion bounds, and fixed external command paths were negative. The log display keeps one user-controlled unbounded child-output buffer finding.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/cli/cli_show.go | show dispatch | negative | redaction/family routing |
| pkg/cli/cli_show_chassis.go | forwarding status | negative | local/peer adapter/timeout |
| pkg/cli/cli_show_chassis_adapter_test.go | chassis test | negative | userspace status projection |
| pkg/cli/cli_show_cluster.go | cluster display | negative | fabric counter/error disclosure |
| pkg/cli/cli_show_cluster_test.go | cluster test | negative | counter index/unloaded state |
| pkg/cli/cli_show_config_redaction_4099_test.go | redaction test | negative | every config/rollback/rescue form |
| pkg/cli/cli_show_effective_filter_4422_test.go | filter test | negative | compiled snapshot fidelity |
| pkg/cli/cli_show_policies_bulk_reader_test.go | counter test | negative | bulk reader use |
| pkg/cli/cli_show_policies_hitcount_gate_test.go | policy test | negative | stats gate |
| pkg/cli/cli_show_policies_scheduler_3062_test.go | scheduler test | negative | scheduler display |
| pkg/cli/cli_show_policies_thencount_3074_test.go | policy test | negative | then-count display |
| pkg/cli/cli_show_routing.go | routing view | negative | kernel error/display-only behavior |
| pkg/cli/cli_show_services.go | service view | negative | absent manager/config behavior |
| pkg/cli/cli_show_services_test.go | service test | negative | RPM/IP-monitor no-config path |
| pkg/cli/cli_show_shared.go | help | negative | static bounded text |
| pkg/cli/cli_show_snmp_community_redaction_4111_test.go | SNMP test | negative | secret redaction |
| pkg/cli/cli_show_system.go | system/log view | A10-b2-F003 | bounded or streaming log output |
| pkg/cli/cli_show_system_buffers_test.go | system test | negative | userspace buffer unavailable state |
| pkg/cli/completion.go | completion | negative | rune/prefix panic guard |
| pkg/cli/completion_activate_test.go | completion test | negative | schema completion |
| pkg/cli/completion_panic_test.go | completion test | negative | overtyped/pipe safety |
| pkg/cli/completion_typed_leaf_test.go | completion test | negative | typed values |
| pkg/cli/configstore_helper_test.go | fixture | negative | isolated store |

### Monitor and remaining tests

Tcpdump argv and count bounds, trace confinement/rotation, raw-terminal reader ownership, event-buffer nil guards, and monitor RBAC were negative. Trace writer failures stop tracing rather than silently lifting the configured cap.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/cli/monitor.go | security monitor | negative | atomic config, confinement, rotation stop |
| pkg/cli/monitor_flow_perm_5038_test.go | monitor RBAC test | negative | file write needs control |
| pkg/cli/monitor_interface.go | interface monitor | negative | reader stops before terminal restore |
| pkg/cli/monitor_interface_stdin_3985_test.go | terminal test | negative | no next-command key theft |
| pkg/cli/monitor_match_test.go | monitor test | negative | regex/filter exactness |
| pkg/cli/monitor_nil_eventbuf_3381_test.go | monitor test | negative | nil event buffer safe |
| pkg/cli/monitor_security_test.go | monitor test | negative | parse/lifecycle |
| pkg/cli/monitor_test.go | trace-file test | negative | nofollow/regular file/rotation |
| pkg/cli/monitor_traffic.go | traffic monitor | negative | `--`, filter rejection, count bound |
| pkg/cli/monitor_traffic_count_bound_4589_test.go | traffic test | negative | count cap |
| pkg/cli/monitor_traffic_filter_4005_test.go | traffic test | negative | multi-token quote handling |
| pkg/cli/monitor_traffic_injection_4524_test.go | traffic test | negative | option injection rejected |
| pkg/cli/monitor_traffic_keyword_4540_test.go | traffic test | negative | missing value fails |
| pkg/cli/monitor_traffic_quotestrip_4556_test.go | traffic test | negative | quoted smuggling rejected |
| pkg/cli/cli_zone_nil_3493_test.go | zone test | negative | nil HA-sync zones safe |

### A10-b3: Services, CLI, build/deploy tooling and unmatched modules (118 files)

Batch-list SHA-256: `9bdeeb8f2d300551cb3cf83d36538a370d5cc2f2490ddf50c7e7ab2f7bd14c5a`.

`negative` means no credible non-duplicate finding survived. Each module sweep assessed correctness/security and fail-open behavior; memory/concurrency/truncation/leaks; relevant vSRX/feature completeness; latency/resource behavior; modularity; and its assigned test coverage. The final column records the principal invariant checked for that individual file.

### CLI

CLI assessment: strict operator parsing and session-key byte order are fail-closed; RPC calls have bounded contexts; no packet-path work applies. Display-only services report unavailable state rather than inventing zeroes. Assigned tests cover selector strictness, stream errors, redaction, and presentation. No surviving finding.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/cli/policymatch_feed_overlay_test.go | CLI policy simulator test | negative | Feed overlay is passed to both local policy-match surfaces; no stale static-only verdict. |
| pkg/cli/policymatch_port_test.go | CLI policy simulator test | negative | Invalid and out-of-range ports reject rather than widening to wildcard. |
| pkg/cli/policymatch_protocol_test.go | CLI policy simulator test | negative | Unknown/out-of-range protocols reject rather than becoming any. |
| pkg/cli/proto.go | CLI protocol helpers | negative | Native-endian map IPv4 reconstruction and network-port conversion remain distinct. |
| pkg/cli/query_strictness_3696_test.go | CLI selector parser test | negative | Missing, empty, and unknown selectors fail command parsing. |
| pkg/cli/runtime.go | CLI runtime contract | negative | Narrow interface contains only required operational reads/mutations. |
| pkg/cli/session_display.go | CLI session interface display | negative | Nil config and unresolved interfaces do not fabricate egress mappings. |
| pkg/cli/session_display_test.go | CLI session interface display test | negative | Unit/VLAN and RETH lookup mappings are deterministic. |
| pkg/cli/session_filter.go | CLI session filtering/RPC | negative | Invalid filter input fails closed; ports are byte-swapped once; peer fetches are timeout-bounded. |
| pkg/cli/session_filter_multi_iface_4792_test.go | CLI session filtering test | negative | Every interface in a multi-interface zone is eligible for show/clear matching. |
| pkg/cli/session_filter_test.go | CLI session filtering test | negative | Zone, address, NAT, app, pool, and interface predicates preserve conjunction semantics. |
| pkg/cli/sessions_iterator_error_test.go | CLI session iteration test | negative | Iterator errors remain visible rather than presenting a partial list as complete. |
| pkg/cli/show_interfaces_queue_5326_test.go | CLI queue display test | negative | Status fetch failure is not displayed as an empty queue set. |
| pkg/cli/show_log_allowlist_4860_test.go | CLI log presentation test | negative | Allowlist presentation retains the configured value and expected status semantics. |
| pkg/cli/show_security_counter_error_test.go | CLI security counters test | negative | Counter errors/unpopulated sentinels are rendered distinctly from zero. |
| pkg/cli/show_services_cos.go | CLI CoS presentation | negative | Userspace-status failure is propagated to queue formatting; no false empty state. |
| pkg/cli/show_services_ddns.go | CLI DDNS presentation | negative | Secret fields are redacted and degraded state remains operator-visible. |
| pkg/cli/show_services_dhcp.go | CLI DHCP presentation | negative | Lease-file errors warn rather than claim a clean empty lease table. |
| pkg/cli/show_services_lldp.go | CLI LLDP presentation | negative | Disabled/unavailable status is explicit; age computation is display-only. |
| pkg/cli/show_services_mirror.go | CLI mirroring presentation | negative | Nil/empty config is handled without a false active instance. |
| pkg/cli/show_services_snmp.go | CLI SNMP presentation | negative | Non-superuser community names are redacted. |
| pkg/cli/testpolicy_icmp_4497_test.go | CLI policy ICMP test | negative | ICMP type/code reaches the simulator and verdict echo. |
| pkg/cli/testpolicy_idscope_3674_test.go | CLI policy identity test | negative | Policy ID, scope, and description track the runtime ID source. |
| pkg/cli/testpolicy_srcport_test.go | CLI policy source-port test | negative | Absent source-port fails closed against source-port-constrained apps. |
| pkg/cli/usage_matchpolicies_3628_test.go | CLI usage test | negative | Advertised selectors match the shared strict parser surface. |
| pkg/cli/zone_flood_counters_hide_test.go | CLI counter presentation test | negative | Unpopulated zone/flood counters are unavailable, not misleading zeroes. |

### DDNS

DDNS assessment: ownership writes are durable before provider I/O; state-load and source-bind failures fail closed; HTTP bodies/timeouts are bounded; provider calls release manager locks; RFC2136 and Cloudflare paths protect value ownership. The state semantic-validation, Cloudflare pagination, DHCP expiry, and relay accounting candidates matched prior reports and were dropped. One Route 53 ownership candidate survived.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/ddns/backend.go | DDNS record contract | negative | Address family, PTR construction, ownership metadata, and no-op backend semantics remain explicit. |
| pkg/ddns/backend_bind.go | DDNS source binding | negative | Invalid source bind fails construction; device/source family binding cannot silently select a mismatched family. |
| pkg/ddns/backend_bind_test.go | DDNS source binding test | negative | Source, device/VRF precedence, and dual-stack family gating are covered. |
| pkg/ddns/backend_cloudflare.go | Cloudflare backend | negative | Content-specific update/delete avoids foreign-record clobber; pagination gap is prior duplicate. |
| pkg/ddns/backend_cloudflare_test.go | Cloudflare backend test | negative | Foreign same-name rows and owned-row delete behavior are covered. |
| pkg/ddns/backend_dualstack_withdraw_3738_test.go | Host-granular provider test | negative | A one-family withdrawal does not blackhole an owned sibling family. |
| pkg/ddns/backend_duckdns.go | DuckDNS backend | negative | Token handling is redacted and host-wide clear is sibling-protected. |
| pkg/ddns/backend_duckdns_test.go | DuckDNS backend test | negative | Request shape, token requirement, verdict parsing, and clear semantics are covered. |
| pkg/ddns/backend_dyndns2.go | dyndns2 backend | negative | Endpoint parsing, credential handling, and sibling-protected offline withdraw are bounded. |
| pkg/ddns/backend_generic.go | Generic DDNS backend | negative | Template validation/redaction and no-delete behavior fail safely. |
| pkg/ddns/backend_generic_porthost_4589_test.go | Generic DDNS validation test | negative | Port-only authority is rejected before a localhost-like fallback. |
| pkg/ddns/backend_http.go | HTTP DDNS shared transport | negative | TLS verification, redirect downgrade refusal, capped bodies, cache locking, and source-bind errors are explicit. |
| pkg/ddns/backend_http_sourcebind_2846_test.go | HTTP source-bind test | negative | Bound and unbound dial paths do not leak a requested source binding. |
| pkg/ddns/backend_http_test.go | HTTP DDNS backend test | negative | Provider verdict parsing, malformed endpoints, token-bound success matching, and delete failure semantics are covered. |
| pkg/ddns/backend_rfc2136.go | RFC2136 backend | negative | Exact-RR/DHCID guards, TCP retry cancellation, TSIG, and PTR partial-success state are preserved. |
| pkg/ddns/backend_rfc2136_test.go | RFC2136 backend test | negative | Ownership prerequisites, exact delete, DHCID sharing, and transport behavior are covered. |
| pkg/ddns/backend_route53.go | Route 53 backend | A10-b3-F001 | Single-record `UPSERT` replaces a whole RRset without preserving unrelated values. |
| pkg/ddns/backend_route53_test.go | Route 53 backend test | negative | Batch formation, errors, idempotent delete, and credentials are covered; no shared-RRset preservation test exists. |
| pkg/ddns/checkip.go | Check-IP oracle | negative | URL/source-bind failures and non-public or allowlisted addresses fail closed. |
| pkg/ddns/checkip_sourcebind_failclosed_3733_test.go | Check-IP bind test | negative | Failed source binding cannot probe through the default route. |
| pkg/ddns/checkip_test.go | Check-IP parser test | negative | Special-use addresses, malformed URLs, and response parsing are covered. |
| pkg/ddns/corrupt_state_durable_4873_test.go | DDNS state durability test | negative | Corrupt-state degraded marker survives restart. |
| pkg/ddns/durability_test.go | DDNS write-ahead test | negative | Add intent is durable before wire I/O and refused adds remove intent. |
| pkg/ddns/hostname.go | DDNS hostname derivation | negative | Client names cannot escape the configured zone and sanitize deterministically. |
| pkg/ddns/manager.go | DHCP DDNS reconciler | negative | Family/scope gates, write-ahead ownership, backend absence, and lock release around I/O are fail-safe. |
| pkg/ddns/manager_inc2_test.go | DHCP DDNS integration test | negative | Live backend lifecycle, conflicts, pending PTR, and no-phantom ownership are covered. |
| pkg/ddns/manager_lockio_5006_test.go | DHCP DDNS concurrency test | negative | Stats/readers do not wait on provider network I/O. |
| pkg/ddns/manager_test.go | DHCP DDNS reconciler test | negative | Reassignment, parse failure, state loading, and non-owned delete exclusions are covered. |
| pkg/ddns/redirect_downgrade_4861_test.go | HTTP redirect test | negative | HTTPS credentials cannot follow a downgrade redirect. |
| pkg/ddns/scope_test.go | DDNS scope/HA test | negative | Scope keys and v4/v6/RG ownership remain independent. |
| pkg/ddns/sigv4.go | Route 53 signing | negative | Canonical URI/query/header ordering and payload signing are deterministic. |
| pkg/ddns/sigv4_test.go | Route 53 signing test | negative | Known-vector signing and query canonicalization are covered. |
| pkg/ddns/spine_fixes_test.go | DDNS spine regression test | negative | Shared DHCID, no-backend ownership, and pending visibility are covered. |
| pkg/ddns/state.go | DDNS ownership state | negative | Durable sorted store and degraded marker protect state; malformed semantic records are a prior duplicate. |
| pkg/ddns/surface_a.go | Surface A DDNS engine | negative | Scope ownership, pending recovery, provider changes, backoff, and lock-release races are handled. |
| pkg/ddns/surface_a_durable_pending_5285_test.go | Surface A durability test | negative | Save-to-wire crash recovery preserves prior confirmed address and retries pending publish. |
| pkg/ddns/surface_a_hostname_2779_test.go | Surface A hostname test | negative | Config validation and runtime normalization agree. |
| pkg/ddns/surface_a_http_test.go | Surface A HTTP test | negative | Engine skips no-backend providers and keeps secrets out of errors. |
| pkg/ddns/surface_a_httpcache_2904_test.go | Surface A HTTP cache test | negative | Per-binding transports are reused and not cross-bound incorrectly. |
| pkg/ddns/surface_a_httpcache_reap_2956_test.go | Surface A cache reaper test | negative | Superseded transports are closed/evicted while live bindings remain. |
| pkg/ddns/surface_a_lockio_test.go | Surface A concurrency test | negative | Status reads proceed while publish/withdraw provider I/O is blocked. |
| pkg/ddns/surface_a_observe_lockio_3736_test.go | Surface A observation test | negative | Check-IP observation releases the lock and honors reconciliation cancellation. |
| pkg/ddns/surface_a_provider_change_3735_test.go | Surface A provider transition test | negative | Endpoint changes retain ownership and surface orphan alarms instead of wrong-endpoint deletes. |
| pkg/ddns/surface_a_provider_transition_4422_test.go | Surface A provider handoff test | negative | Provider transitions preserve clean handoff and do not withdraw unchanged ownership. |
| pkg/ddns/surface_a_rfc2136_test.go | Surface A RFC2136 test | negative | Renumbering preserves foreign records and uses exact self-owned replacement. |
| pkg/ddns/surface_a_sourcebind_failclosed_4437_test.go | Surface A source-bind test | negative | Cached-client bind failure resolves to no-op, never default-route publish. |
| pkg/ddns/surface_a_test.go | Surface A engine test | negative | Address observation, forced refresh, degraded state, status ordering, and address-loss behavior are covered. |
| pkg/ddns/surface_a_withdraw_backoff_2813_test.go | Surface A withdrawal test | negative | Withdraw failures back off and unsupported deletes retain visible ownership. |

### Device Map

Device-map assessment: matching is deterministic, rejects PCI/MAC ambiguity and duplicate NIC claims, and excludes virtual interfaces. Enumeration has no packet-path role; sysfs/netlink failures do not bind a guessed interface. Tests cover PCI and non-PCI hardware identities. No surviving finding.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|---|
| pkg/devicemap/devicemap.go | Device identity resolver | negative | PCI/MAC topology mismatch, ambiguity, and cross-key double claims are refused. |
| pkg/devicemap/devicemap_nonpci_4884_test.go | Device enumeration test | negative | Physical non-PCI NICs remain eligible for MAC-only mapping. |
| pkg/devicemap/devicemap_test.go | Device identity resolver test | negative | Key order, RETH restrictions, fallback labels, and reorder stability are covered. |

### DHCP Client

DHCP-client assessment: client registry and callbacks are lock-safe, renewal packet state is protocol-specific, DHCPv4 masks and DHCPv6 IA/PD results are validated, and netlink work is outside the forwarding path. The indefinite expired-address/PD retention behavior is a prior duplicate. Assigned tests exercise renewal, NAK, expiry, route, DUID traversal, and config-reconcile edges. No surviving finding.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|
| pkg/dhcp/classless_routes_test.go | DHCPv4 routes test | negative | Option 121/249 supersedes option 3 and preserves specific/default route semantics. |
| pkg/dhcp/clearduid_traversal_4857_test.go | DHCP DUID filesystem test | negative | Interface names cannot traverse out of the DUID state directory. |
| pkg/dhcp/commit.go | DHCP lease commit | negative | Address replacement, PD withdrawal/silence behavior, and callbacks are serialized correctly. |
| pkg/dhcp/commit_test.go | DHCP lease commit test | negative | Renewal timers and lease/PD content-change gating are covered. |
| pkg/dhcp/dhcp.go | DHCP client runtime | negative | Renewal/rebind/NAK handling, address validation, DUID paths, and v6 selection are fail-safe; expiry retention is prior duplicate. |
| pkg/dhcp/dhcp_lease_expiry_4874_test.go | DHCP expiry/PD test | negative | NAK teardown, recompilation, and explicit PD withdrawal are covered. |
| pkg/dhcp/dhcp_test.go | DHCP client test | negative | PD parsing, modifiers, prefix derivation, and option state are covered. |
| pkg/dhcp/dhcpv6_iana_test.go | DHCPv6 IA_NA test | negative | Multiple IAADDR choices are deterministic and zero-valid-lifetime addresses reject. |
| pkg/dhcp/gateway_hook_test.go | DHCP gateway hook test | negative | Gateway updates fire outside the manager lock and successor cleanup is guarded. |
| pkg/dhcp/reconcile.go | DHCP client config reconcile | negative | Desired membership/fingerprints prevent stale client resurrection and restart only on config changes. |
| pkg/dhcp/reconcile_test.go | DHCP client reconcile test | negative | Start/stop/restart ordering and Renew-versus-removal race are covered. |
| pkg/dhcp/renew.go | DHCP renewal builders | negative | Renew/rebind destinations, server IDs, IA_NA/IA_PD echo, and context waits are correct. |
| pkg/dhcp/renew_test.go | DHCP renewal test | negative | v4/v6 true renewal and immediate NAK deconfiguration are covered. |
| pkg/dhcp/test_seams.go | DHCP test seams | negative | Test-only lifecycle accessors do not widen production behavior. |

### DHCP Relay

DHCP-relay assessment: receive buffers cover valid UDP DHCP datagrams; source-server allowlisting and hop checks fail closed; socket sessions have cancellation joins and interface/giaddr drift rebuilds; raw L2 delivery bounds MTU and falls back to broadcast. The all-server-send counter issue is a prior duplicate. No surviving finding.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|
| pkg/dhcprelay/delivery_test.go | DHCP relay delivery test | negative | Reply matrix, NAK/FORCERENEW, saved giaddr, and configured-server allowlist are covered. |
| pkg/dhcprelay/l2send_linux.go | DHCP relay raw L2 | negative | Ethernet/IPv4/UDP bounds, endianness, checksum, MTU guard, and close lifecycle are correct. |
| pkg/dhcprelay/l2send_test.go | DHCP relay raw L2 test | negative | Frame bytes, checksum, host/network conversion, and captured MAC behavior are covered. |
| pkg/dhcprelay/relay.go | DHCP relay runtime | negative | HA gate, hop precheck, source validation, join/cancel lifecycle, and rebind detection are fail-safe; send counter is prior duplicate. |
| pkg/dhcprelay/relay_giaddr_linux.go | DHCP relay giaddr lookup | negative | Netlink primary-address selection avoids secondary-address giaddr choice. |
| pkg/dhcprelay/relay_giaddr_linux_test.go | DHCP relay giaddr test | negative | Secondary ordering, fallback, and empty-address handling are covered. |
| pkg/dhcprelay/relay_test.go | DHCP relay lifecycle test | negative | Option 82, startup retry, socket closure, HA transition, and drift/readdress rebuilds are covered. |
| pkg/dhcprelay/sockopt_linux.go | DHCP relay socket setup | negative | Reuse, interface binding, and broadcast options are applied before bind. |

### DHCP Server

DHCP-server assessment: systemd status uncertainty is surfaced and enforced conservatively; apply generations serialize sync/async changes; lease parsers distinguish destructive DDNS from lenient display; lease-sync uses bounded Kea control I/O and atomic memfile handoff. Assigned tests cover active state, lease type, expiry, owner permissions, reservations, and subnet IDs. No surviving finding.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|
| pkg/dhcpserver/ddns.go | DHCP-server DDNS adapter | negative | Kea lease type reaches DDNS so IA_PD cannot publish host DNS. |
| pkg/dhcpserver/ddns_iapd_5072_test.go | DHCP-server DDNS test | negative | Mixed IA_NA/IA_PD input publishes only address-bearing leases. |
| pkg/dhcpserver/ddns_integration_test.go | DHCP-server DDNS integration test | negative | Real parser-to-reconciler active lease lifecycle remains wired. |
| pkg/dhcpserver/ddns_leases.go | Destructive Kea lease parser | negative | Header/ragged/duplicate failure marks source untrusted; active final row and identity selection are safe. |
| pkg/dhcpserver/ddns_leases_test.go | Destructive Kea lease parser test | negative | Header validation, last-row state, optional fields, and row shape fail-safe behavior are covered. |
| pkg/dhcpserver/dhcpserver.go | Kea config/lifecycle manager | negative | Unit-state uncertainty, generation supersession, atomic config, deterministic subnet IDs, and reservation rendering are controlled. |
| pkg/dhcpserver/dhcpserver_isactive_error_4870_test.go | Kea lifecycle error test | negative | Uncertain unit state forces enforcement and returns an error. |
| pkg/dhcpserver/dhcpserver_test.go | Kea lifecycle/config test | negative | Apply/clear, async ordering, display parsing, selectors, and subnet IDs are covered. |
| pkg/dhcpserver/expired_leases_test.go | Kea expiry config test | negative | Per-family omission/default/zero semantics remain unambiguous. |
| pkg/dhcpserver/lease_sync.go | DHCP HA lease sync | negative | Bounded socket I/O, remaining-lifetime re-anchoring, identity/type preservation, and atomic pre-seed are guarded. |
| pkg/dhcpserver/lease_sync_test.go | DHCP HA lease sync test | negative | Socket/memfile paths, expired rejection, local-union preseed, IA types, and ownership permissions are covered. |
| pkg/dhcpserver/reservations_test.go | Kea reservation test | negative | v4/v6 reservation shape and MAC canonicalization are covered. |
| pkg/dhcpserver/test_seams.go | DHCP-server test seams | negative | Test injection is confined to lifecycle/lease-sync observability. |

### Diagnostics And Fairness

Assessment: diagnostic argv construction uses an option terminator and a single VRF normalization; the process-wide limiter is a nonblocking, idempotent-release semaphore. RSS expectation parsing rejects non-finite/out-of-range values and evaluation uses overflow-safe flow accumulation. No relevant vSRX or packet-path behavior; assigned tests cover these contracts. No surviving finding.

| Path | Subsystem | Result | Invariant checked |
|---|---|---|
| pkg/diagcmd/diagcmd.go | Diagnostic argv builder | negative | Target option injection is blocked with `--`; VRF prefix is applied exactly once. |
| pkg/diagcmd/diagcmd_test.go | Diagnostic argv test | negative | Ping/traceroute argv order, source, VRF, and dash-prefixed targets are covered. |
| pkg/diagcmd/limiter.go | Diagnostic limiter | negative | Global capacity is fail-fast and each release returns exactly one slot. |
| pkg/diagcmd/limiter_test.go | Diagnostic limiter test | negative | Capacity, idempotent release, and concurrent rejection/drain behavior are covered. |
| pkg/fairness/expectation.go | RSS fairness evaluator | negative | Parser rejects NaN/Inf/out-of-range values; sums are uint64 and empty traffic fails non-any expectations. |
| pkg/fairness/expectation_test.go | RSS fairness evaluator test | negative | Canonical parsing, metric shape, balanced/skew/no-traffic results are covered. |

### A10-b4: Services, CLI, build/deploy tooling and unmatched modules (83 files)

Batch-list SHA-256: `78103d28238856923c19f7f0617d1d7ca08e95b1416786b39016451d197f3dfa`.

### fsatomic
Assessment: atomic/durable replacement preserves pre/post-rename error distinction and cleanup; no unsafe memory or packet path exists. Symlink/mode/owner and fsync boundaries are covered, with no vSRX gap or latency concern beyond documented durable fsync. Canary and failure-injection tests cover the modular writer contract.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/fsatomic/canary_test.go | negative | AST canary rejects unapproved direct durable-state writes. |
| pkg/fsatomic/fsatomic.go | negative | Temp write, metadata, optional fsync, rename, and post-rename directory sync preserve atomicity/durability classification. |
| pkg/fsatomic/fsatomic_test.go | negative | Error stages, ownership, symlink behavior, concurrent replacement, and fsync boundaries retain the old file or classify visible new content. |

### fwdstatus
Assessment: `/proc` parsers fail to Unknown rather than fabricate health; sampler locking protects the ring and cached helper telemetry avoids a new poll. No unsafe memory, forwarding mutation, vSRX enforcement gap, or unbounded hot path was found. Existing tests cover parser failures, heartbeat freshness, counters, and windows. The pre-division tick-overflow candidate is duplicate-suppressed.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/fwdstatus/builder.go | negative | Health is Unknown for absent dataplane/proc/helper status and userspace buffer telemetry is bounded/clamped. |
| pkg/fwdstatus/fwdstatus.go | negative | Rendering preserves explicit Unknown/Degraded state and bounded percentage formatting. |
| pkg/fwdstatus/fwdstatus_test.go | negative | Output, helper-state, heartbeat, and buffer-utilization regression cases are covered. |
| pkg/fwdstatus/osprocreader_test.go | negative | Malformed proc fixtures fail rather than supply invented counters. |
| pkg/fwdstatus/procreader.go | negative | Proc field parsing validates length and numeric conversion; unreadable cgroup data falls back safely. |
| pkg/fwdstatus/sampler.go | negative | Mutex-protected ring, counter-reset checks, and cached-status-only worker telemetry preserve rate correctness. |
| pkg/fwdstatus/sampler_test.go | negative | Cached-status, short-history, non-monotonic counter, and formatting paths are exercised. |

### ipmon
Assessment: overlay winner resolution, resolver locking, debounce/throttle, timeout retry, and HA publication gating were traced. The engine keeps the last converged overlay deliberately, which is correct for FIB convergence; the renderer loses that fact when a withdrawal is pending (A10-b4-F001). No memory-unsafe implementation exists; slow control-plane work is bounded by a context timeout. Tests cover many state-machine paths but omit an already-applied route whose withdrawal fails.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/ipmon/display.go | A10-b4-F001 | Route-action output must distinguish live applied routes from desired withdrawals pending convergence. |
| pkg/ipmon/ipmon.go | A10-b4-F001 | `appliedOverlay` remains last-converged until a successful replacement and status must expose it accurately. |
| pkg/ipmon/ipmon_test.go | negative | State, convergence, retry, lifecycle, gating, and overlay filtering are tested; withdrawal presentation is not. |
| pkg/ipmon/nexthop_test.go | negative | Interface next-hop resolution, loss, takeover gate, and coalescing preserve a single overlay path. |

### linuxsock
Assessment: raw socket creation forces atomic CLOEXEC and the AST canary prevents bypasses. This is a narrow modular security boundary; no concurrency, truncation, leak, vSRX, or packet-latency finding survived.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/linuxsock/canary_test.go | negative | Every production direct `unix.Socket` use is forbidden except reviewed CLOEXEC sites. |
| pkg/linuxsock/linuxsock.go | negative | SOCK_CLOEXEC is ORed into the creation syscall, eliminating the fork-exec interval. |
| pkg/linuxsock/linuxsock_test.go | negative | Seam and real-FD checks prove CLOEXEC is passed and installed. |

### lldp
Assessment: AF_PACKET receive handling bounds frames, rejects truncated mandatory TLVs, sanitizes terminal/log control characters, rate-limits cap logs, and closes sockets before waiting. Neighbor state is bounded per interface. One low-confidence-area candidate became a High-confidence Low finding: delimiter-concatenated keys are not injective for valid opaque identifiers (A10-b4-F002). The TTL-zero delayed deletion candidate is duplicate-suppressed.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/lldp/lldp.go | A10-b4-F002 | A local-interface/chassis/port tuple must map to a collision-free bounded neighbor identity. |
| pkg/lldp/lldp_test.go | negative | TLV bounds, mandatory fields, sanitizer, TTL encoding, and table-cap behavior are covered. |
| pkg/lldp/socket_test.go | negative | Socket close unblocks RX; error retry/backoff, self-frame filtering, and flood caps are covered. |

### monitoriface
Assessment: snapshot/rate arithmetic clamps counter resets and aggregates userspace telemetry only with a coherent source. It is display-only, modularly adapts dataplane state, and its scans are CLI/stream diagnostics rather than packet path. Per-interface `Status()` polling is a duplicate of the already-tracked redundant control-socket poll root cause (#3970), so it is not retained. Tests cover aggregation and alias choice; no new correctness or vSRX finding survived.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/monitoriface/monitor.go | negative | Display counters/rates avoid unsigned underflow and alias selection maps one display row to one kernel source. |
| pkg/monitoriface/monitor_test.go | negative | Userspace aggregation, reset behavior, disappearance handling, and fabric/RETH deduplication are covered. |

### natpoolalarm
Assessment: coherent cached views gate alarm transitions; nil/mid-apply data does not silently clear a live alarm, and syslog is emitted only on transitions outside the mutex. Arithmetic widens port bounds before subtraction. This is control-plane observability, not the forwarding path; no vSRX, concurrency, or performance finding survived.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/natpoolalarm/natpoolalarm.go | negative | Available/coherent generations, eligibility, hysteresis, and bounded synchronized active state preserve alarm semantics. |
| pkg/natpoolalarm/natpoolalarm_test.go | negative | Raise/clear, invalid config, unavailable data, threshold boundaries, and lifecycle are covered. |
| pkg/natpoolalarm/render.go | negative | Alarm output is deterministic for empty, summary, and detail views. |
| pkg/natpoolalarm/render_test.go | negative | Render shape/count behavior is covered. |

### natshow
Assessment: NAT displays are read-only and share CLI/gRPC renderers. v4 native-endian recovery and v6 `netip` keys were traced; session traversals are diagnostic-only. The mutable persistent-table pointer candidate is already tracked and is not retained. No new display/parity/fail-open issue survived.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/natshow/dest.go | negative | Destination NAT session/count views select forward DNAT entries and tolerate unavailable reads. |
| pkg/natshow/natshow.go | negative | Reader boundary is narrow and nil-safe. |
| pkg/natshow/natshow_test.go | negative | Source/destination/static/NPTv6/persistent output and byte-order paths are covered. |
| pkg/natshow/persistent.go | negative | Persistent bindings use family-safe `netip` keys and native-endian v4 reconstruction. |
| pkg/natshow/source.go | negative | Source NAT session/count views select forward SNAT entries and render defaults safely. |
| pkg/natshow/static.go | negative | Static/NPTv6 display preserves configured fields without runtime mutation. |

### nftables
Assessment: counter readers distinguish absent tables from read errors, parsers reject foreign names, and RST suppression batches delete/recreate atomically. No packet-path allocation, unsafe memory, or fail-open rule-construction condition was found in scope. Tests cover name safety and plan behavior; live netlink integration remains environment-dependent.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/nftables/host_inbound_accept_counters.go | negative | Fixed accept-counter names cannot cross-parse deny/foreign objects. |
| pkg/nftables/host_inbound_accept_counters_test.go | negative | Accept counter round-trip, nft-safe identifiers, and foreign rejection are covered. |
| pkg/nftables/host_inbound_counters.go | negative | Length-prefixed sanitized zone counter names parse only valid IP/IP6 objects. |
| pkg/nftables/host_inbound_counters_test.go | negative | Deny counter round-trip, sanitization, and malformed-name rejection are covered. |
| pkg/nftables/host_inbound_junos_host_counters.go | negative | Junos-host counters use a separate validated namespace and report netlink errors. |
| pkg/nftables/lo0_counters.go | negative | lo0 counter names are prefixed/sanitized and absent tables do not fabricate zero data. |
| pkg/nftables/lo0_counters_test.go | negative | lo0 round-trip, foreign rejection, and exotic-byte sanitation are covered. |
| pkg/nftables/rst_suppress.go | negative | Existing RST table replacement is queued atomically; v4/v6 source offsets and family gates are explicit. |
| pkg/nftables/rst_suppress_test.go | negative | Missing-table and delete-only plans avoid spurious delete batches. |

### policymatch
Assessment: the simulator is explicitly a control-plane parity surface and consistently fails closed on unsupported content, unknown zones, missing constrained tuple fields, malformed selectors, and scheduler inactivity. Address recursion has cycle protection; no packet allocation or concurrency path exists here. Extensive parity tests cover wildcard/global/host/content/selector/ICMP behavior; no new runtime divergence survived.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/policymatch/app_icmp_code_4422_test.go | negative | ICMP type/code application constraints require exact values. |
| pkg/policymatch/app_junos_ping_3348_test.go | negative | Predefined ping application protocol/type parity is preserved. |
| pkg/policymatch/app_set_failclosed_3727_test.go | negative | Unexpandable application sets reject the whole simulated config. |
| pkg/policymatch/app_srcdst_port_range_4413_test.go | negative | Source and destination port-range terms both constrain matching. |
| pkg/policymatch/content_reject_4394_test.go | negative | Unsupported app/protocol/address content surfaces whole-snapshot fail-close. |
| pkg/policymatch/display_action_3375_test.go | negative | Host/default/content-rejected action display remains single-source. |
| pkg/policymatch/empty_zone_4411_test.go | negative | Empty zone policy sets fall through to default policy. |
| pkg/policymatch/excluded_addr_3356_test.go | negative | Excluded address sets use both-family fail-closed semantics. |
| pkg/policymatch/excluded_response_3668_test.go | negative | Matched result exposes exclusion flags and stable IDs. |
| pkg/policymatch/global_scope_regression_4365_test.go | negative | Scoped global precedence and undefined scopes are fail-closed. |
| pkg/policymatch/global_zone_filter_3357_test.go | negative | Global display filtering follows scope applicability. |
| pkg/policymatch/host_inbound_token_3627_test.go | negative | Host admission token classification stays in the host-only path. |
| pkg/policymatch/host_inbound_verdict_msg_3627_test.go | negative | Host unmatched wording does not claim transit/default enforcement. |
| pkg/policymatch/icmp_test.go | negative | ICMP type matching and parser values retain nil-versus-zero distinction. |
| pkg/policymatch/junos_host_test.go | negative | Junos-host uses exact/wildcard/global host precedence without transit fallback. |
| pkg/policymatch/policymatch.go | negative | Selector validation, policy tiers, address/app parity, and content rejection are fail-closed. |
| pkg/policymatch/policymatch_test.go | negative | Shared matcher regression matrix covers precedence and feed/address behavior. |
| pkg/policymatch/port_omitted_3330_test.go | negative | Omitted destination port cannot match a port-constrained app. |
| pkg/policymatch/port_test.go | negative | Port ranges and parser bounds reject invalid tuple values. |
| pkg/policymatch/protocol_omitted_3323_test.go | negative | Omitted protocol cannot match protocol-constrained applications. |
| pkg/policymatch/protocol_test.go | negative | Protocol validator rejects unknown/out-of-range protocol tokens. |
| pkg/policymatch/reject_matrix_4422_test.go | negative | Reject policy result remains distinct from deny/default. |
| pkg/policymatch/route_drop_4373_test.go | negative | Non-routable transit destinations carry route-before-policy advisory. |
| pkg/policymatch/scheduler_test.go | negative | Inactive scheduled rules are skipped before tuple matching. |
| pkg/policymatch/scope_id_3331_test.go | negative | Policy IDs/scopes match runtime inventory namespace. |
| pkg/policymatch/scoped_global_zonelocal_test.go | negative | Scoped global and zone-local book resolution retain their separate semantics. |
| pkg/policymatch/scoped_global_zoneset_4626_test.go | negative | Multi-zone global scopes render/restrict concrete flow zones correctly. |
| pkg/policymatch/selector_args_3696_test.go | negative | Missing/unknown/malformed selectors fail instead of widening a query. |
| pkg/policymatch/selector_args_dup_3709_test.go | negative | Duplicate selectors are rejected rather than last-win. |
| pkg/policymatch/simulator_output_parity_3685_test.go | negative | Simulator metadata carries scheduler and description consistently. |
| pkg/policymatch/srcport_omitted_3415_test.go | negative | Omitted source port cannot match a source-port-constrained app. |
| pkg/policymatch/undefined_zone_3355_test.go | negative | Undefined zones bypass transit/global/wildcard tiers to default. |
| pkg/policymatch/usage_3628_test.go | negative | Usage advertises all accepted tuple selectors. |
| pkg/policymatch/wildcard_scoped_test.go | negative | Exact/single/both wildcard tiers precede scoped globals. |
| pkg/policymatch/zone_detail_summary.go | negative | Zone summary preserves runtime tier ordering, IDs, scheduler/log/count metadata. |
| pkg/policymatch/zone_detail_summary_test.go | negative | Summary includes wildcard/global/default paths and honest unknown scheduler state. |
| pkg/policymatch/zone_local_display_3358_test.go | negative | Display unqualifies zone-local names without changing matching tokens. |

### scheduler
Assessment: state transitions and retry are synchronized, time parsing is local-zone aware, and incomplete/unparseable windows fail closed. This is a scheduled policy control path, with a 60-second bounded cadence and no unsafe/packet allocation behavior. Tests cover date/time, per-day, discontinuity, and failed republish paths; no new vSRX parity issue survived.

| Path | Result | Invariant checked |
|---|---|---|
| pkg/scheduler/scheduler.go | negative | Active state is copied under lock; malformed/missing windows and wall-clock discontinuity fail closed; failed publish retries. |
| pkg/scheduler/scheduler_3849_test.go | negative | Per-day overrides, excludes, all-day, and incomplete windows are covered. |
| pkg/scheduler/scheduler_localtz_3988_test.go | negative | Date boundaries use local midnight and stop dates are inclusive. |
| pkg/scheduler/scheduler_republish_3780_test.go | negative | Failed transitions remain pending and self-heal on later ticks. |
| pkg/scheduler/scheduler_test.go | negative | Daily/overnight windows, updates, discontinuity hold, and state snapshots are covered. |

### A10-b5: Services, CLI, build/deploy tooling and unmatched modules (102 files)

Batch-list SHA-256: `f08d14886310cd42da34de47b6b9eea6b3b14acd10ed265cbb2783eda9bcb8b2`.

### Upgrade control, HA, and runtime lifecycle

Scope: transactional cut/rollback, control-socket failure behavior, durable
state, lock ownership, kernel A/B recovery, and vSRX cluster continuity. I
traced the state-machine and rolling call chains through stop, flip, helper
readiness, rejoin, kernel promotion, and cleanup. The retained issue is in the
external HA deploy driver, not this module. Prior candidate roots involving an
unreadable BootCurrent, self-recovery's semantic-empty lease, and already-known
XSK cleanup paths were suppressed.

| Path | Result | Invariant checked |
|---|---|---|
| `pkg/upgrade/cluster_cli.go` | negative | Status parsers require peer ownership, sync, and every RG; malformed text fails closed. |
| `pkg/upgrade/cluster_cli_test.go` | negative | Parser fixtures cover format drift, RG pairing, and fail-closed tokens. |
| `pkg/upgrade/cutover.go` | negative | Journaled preflight/copy/verify remain pre-stop; generation identity and rollback paths do not delete live state. |
| `pkg/upgrade/cutover_cluster_gate_5284_test.go` | negative | Cluster marker blocks bare cut before StopUnit and permits only coordinated rolling. |
| `pkg/upgrade/cutover_refuse_test.go` | negative | Missing rollback/source/version conditions refuse before destructive phases. |
| `pkg/upgrade/flip.go` | negative | Symlink/drop-in flip is durable and rollback restores DB before old binary start. |
| `pkg/upgrade/helper_health.go` | negative | Unit active plus armed/forwarding target-version helper is required within a bounded poll. |
| `pkg/upgrade/helper_health_5286_test.go` | negative | Stale helper, inactive unit, and wrong executable-version cases fail closed. |
| `pkg/upgrade/imageversions.go` | negative | Mixed-base protocol parsing bounds unsigned fields and rejects missing/unknown compatibility evidence. |
| `pkg/upgrade/imageversions_test.go` | negative | Go image gate test coverage includes malformed, zero, and skewed protocol values. |
| `pkg/upgrade/kernel.go` | negative | Kernel state ordering and A/B slot contract preserve known-good boot. |
| `pkg/upgrade/kernel_drain.go` | negative | Drain/rejoin wait bounded predicates and resets incomplete drain. |
| `pkg/upgrade/kernel_drain_test.go` | negative | Deadline and failure-to-failback cases remain operator-visible. |
| `pkg/upgrade/kernel_linux.go` | negative | UEFI parsing, watchdog errors, package holds, and beacon gate use bounded command outcomes. |
| `pkg/upgrade/kernel_linux_test.go` | negative | Linux adapter parsing and watchdog/kernel package boundaries have focused coverage. |
| `pkg/upgrade/kernel_run.go` | negative | Arm-before-BootNext journaling, promotion gates, bounded revert, and no-prune-on-indeterminate behavior reviewed. |
| `pkg/upgrade/kernel_selfrecover.go` | negative | Only a valid expired local lease can accumulate grace; observation errors reset it. |
| `pkg/upgrade/kernel_selfrecover_test.go` | negative | Lease parse, continuous observation, armed state, and peer-primary guards tested. |
| `pkg/upgrade/kernel_test.go` | negative | Kernel state-machine failure/reboot tests cover the destructive-transition boundaries. |
| `pkg/upgrade/lock/lock.go` | negative | One inode-backed nonblocking flock; owner metadata cannot create a split lock. |
| `pkg/upgrade/lock/lock_test.go` | negative | Busy, release, owner truncation, and metadata failure cases tested. |
| `pkg/upgrade/lock_integration_test.go` | negative | Binary and kernel mutation entry points share the host lock. |
| `pkg/upgrade/lock_seam_test.go` | negative | Lock acquisition/release seam prevents regression to nested flock behavior. |
| `pkg/upgrade/manifest/manifest.go` | negative | Fresh manifest slices keep the lockstep binary SSOT immutable to callers. |
| `pkg/upgrade/manifest/manifest_drift_test.go` | negative | Shell/Go managed-binary declarations are checked for drift. |
| `pkg/upgrade/read_journal_malformed_4876_test.go` | negative | Malformed durable journal blocks generation GC instead of discarding protection. |
| `pkg/upgrade/rolling.go` | negative | Peer/sync/protocol/readiness gates precede demotion and rejoin is bounded. |
| `pkg/upgrade/rolling_test.go` | negative | Rolling precondition, drain, rejoin, and operator-driven HA failure paths tested. |
| `pkg/upgrade/runner.go` | negative | Version/path validation, durable journal transitions, fsync copy, and partial cleanup reviewed. |
| `pkg/upgrade/runner_test.go` | negative | State-machine, copy, rollback, and source-generation scenarios exercised. |
| `pkg/upgrade/runtime/seed.go` | negative | First-install runtime seed atomically establishes a usable rollback target and links all managed binaries. |
| `pkg/upgrade/runtime/seed_test.go` | negative | Seed idempotency, validation, and staged-generation publication tested. |
| `pkg/upgrade/stagedgen/fsutil.go` | negative | Copy rejects unsupported files and syncs nested parent directories before publication. |
| `pkg/upgrade/stagedgen/stagedgen.go` | negative | Bare validated generation IDs, atomic current-gen, and additive protected GC reviewed. |
| `pkg/upgrade/stagedgen/stagedgen_test.go` | negative | Publish, resolve, partial sweeping, and GC protection coverage present. |
| `pkg/upgrade/stagedgen_cut_test.go` | negative | Cut pins immutable source generation across concurrent publishes/resume. |
| `pkg/upgrade/state.go` | negative | Unknown/rollback state does not satisfy forward milestones. |
| `pkg/upgrade/system_linux.go` | negative | Exec argument boundaries, verifier exit semantics, and configured-unit readiness observed. |
| `pkg/upgrade/system_linux_test.go` | negative | Command/version/health adapter behavior tested. |
| `pkg/upgrade/verify_cleanup_test.go` | negative | Verify-failure cleanup rewinds durable state without deleting protected runtime. |
| `pkg/upgrade/version.go` | negative | Version tokens cannot escape version/dotfile namespaces. |
| `pkg/upgrade/version_test.go` | negative | Path, control, whitespace, and non-ASCII rejection tested. |

### WireGuard key utility

Scope: key length, clamping, conversion bounds, and secret handling. No packet
path or vSRX parity surface is introduced; the package is pure and has no
concurrency or allocation-on-forwarding-path concern.

| Path | Result | Invariant checked |
|---|---|---|
| `pkg/wgkey/wgkey.go` | negative | X25519 private input is exactly 32 bytes; random-read failures and oversized hex are rejected. |
| `pkg/wgkey/wgkey_test.go` | negative | Canonical base64, clamping, malformed key, and public derivation coverage present. |

### Deployment, image, distribution, and smoke tooling

Scope: signed artifact consumption/publication, destructive cleanup ownership,
day-0 secret permissions, HA orchestration, and CLI argument boundaries. These
tools are off the forwarding hot path; latency review focused on bounded polling
and avoiding high-rate control-socket traffic. Existing duplicate roots for
identifier path traversal, unsigned base-image checksums, skip-validate signing,
mutable post-verification artifact use, and fixed-name validation cleanup were
not retained.

| Path | Result | Invariant checked |
|---|---|---|
| `scripts/deploy/test_xpf_deploy_correctness.py` | negative | Deploy preflight, config validation, and backend command-shape regressions covered. |
| `scripts/deploy/test_xpf_deploy_disk.py` | negative | Per-VM qcow2 overlays preserve golden-image immutability. |
| `scripts/deploy/test_xpf_deploy_gate.py` | negative | Signed manifest/mixed-base gate behavior and failure handling reviewed. |
| `scripts/deploy/test_xpf_deploy_iso_mode.py` | negative | Day-0 medium creation and ownership-mode tests reviewed. |
| `scripts/deploy/test_xpf_deploy_nicorder.py` | negative | Virtio-before-hardware NIC ordering prevents vSRX zone swap. |
| `scripts/deploy/test_xpf_deploy_robustness.py` | negative | Partial-create cleanup and shell-quoting regression coverage reviewed. |
| `scripts/deploy/xpf-deploy.py` | A10-b5-F001 | HA lease is accepted with non-positive TTL, so the intended cross-driver mutex can expire before either drain. |
| `scripts/dist/publish.py` | negative | Gate rejects unsigned/orphan/symlinked publish inputs and validates all suites/channels before dispatch. |
| `scripts/dist/sign.py` | negative | Signed text uses private verified copies; artifact hashes reject missing/duplicate/pathful manifest entries. |
| `scripts/image/bake.py` | negative | Build/validation/sign ordering and kernel image constraints reviewed; known base-checksum and skip-validation roots suppressed. |
| `scripts/image/make_config_drive.py` | negative | Temporary config content and resulting ISO are owner-only. |
| `scripts/image/test_bake_sign_ordering.py` | negative | Signed image artifacts cannot precede successful validation. |
| `scripts/image/test_validate_scenarios.py` | negative | Scenario selection and validation helpers retain hard-failure behavior. |
| `scripts/image/validate.py` | negative | Signature, qcow2, boot, and day-0 gates are bounded; known fixed-alias cleanup root suppressed. |
| `scripts/iperf-json-metrics.py` | negative | Stream/JSON parsing exposes incomplete/collapse state rather than masking counters. |
| `scripts/mtr_report_check.py` | negative | Missing/unparseable IPv4 destination evidence fails closed; IPv6 relaxation is observability-only by contract. |
| `scripts/test_mtr_report_check.py` | negative | First-hop and final-hop report classification coverage present. |
| `scripts/userspace_ha_validation_matrix_test.py` | negative | HA smoke matrix covers expected validation legs and status/result contracts. |

### Incus scheduler, fairness, and latency evidence

Scope: evidence schema validation, finite arithmetic, bounded subprocesses,
exit-code propagation, aggregate verdicts, and distinction between diagnostic
classification and a forwarding claim. These files do not run per packet. I
checked that event/histogram parsing rejects partial or non-finite evidence,
that control actions use bounded timeouts, and that vSRX/CoS fixtures maintain
the positional interface and policy scheduler contracts. Existing duplicate
roots for false PASS on mouse aggregate/fairness-exit mismatch and empty
evidence classification were suppressed.

| Path | Result | Invariant checked |
|---|---|---|
| `test/incus/cluster_status_parse.py` | negative | RG/node/state parser preserves `secondary-hold` and deterministic ordering. |
| `test/incus/cluster_status_parse_test.py` | negative | Cluster status parse drift and malformed cases tested. |
| `test/incus/cold-path-flooder/src/main.rs` | negative | Frame bounds/checksum/byte order, AF_PACKET ownership, atomic stats, batch limits, and worker shutdown reviewed. |
| `test/incus/cos_be_contention_validate.py` | negative | CoS status/iperf artifacts require finite positive evidence and correct queue deltas. |
| `test/incus/cos_be_contention_validate_test.py` | negative | Queue mapping, malformed artifacts, and contention verdict failures tested. |
| `test/incus/cos_port_grid_test.py` | negative | Fixture ports/classes/caps remain aligned with scheduler and fairness harnesses. |
| `test/incus/fairness_cov.py` | negative | Coefficient-of-variation helper handles empty and degenerate samples explicitly. |
| `test/incus/fairness_cov_test.py` | negative | Fairness CoV edge cases covered. |
| `test/incus/fairness_equal_flow_capture.py` | negative | Capture uses bounded process control and writes only validated aggregate evidence. |
| `test/incus/fairness_multi_sample.py` | negative | Per-run timeout/process-group cleanup and strict verdict schema reviewed; historical exit/verdict mismatch root suppressed. |
| `test/incus/fairness_multi_sample_test.py` | negative | Threshold, schema, timeout, and artifact tests present; cooldown assertion is scheduling-sensitive in a full batch. |
| `test/incus/fairness_surplus_giveback_validate.py` | negative | Required phases, finite rates/drops, and actual give-back transition are validated. |
| `test/incus/fairness_surplus_giveback_validate_test.py` | negative | Missing phase, malformed sample, and handback verdict tests reviewed. |
| `test/incus/iperf3_sum_parse.py` | negative | Iperf summary parser rejects absent/bad aggregate evidence. |
| `test/incus/iperf3_sum_parse_test.py` | negative | TCP/UDP and malformed sum parsing covered. |
| `test/incus/mouse_latency_aggregate.py` | negative | Only valid reps enter percentile selection; insufficient/invalid data is not a PASS. |
| `test/incus/mouse_latency_aggregate_test.py` | negative | Representative percentile, invalid markers, and aggregate gate coverage present. |
| `test/incus/mouse_latency_orchestrate.py` | negative | CoS cap parsing, settle/collapse gates, and empty RG polls fail safely. |
| `test/incus/mouse_latency_orchestrate_test.py` | negative | Settle, collapse, state-flap, and fixture consistency branches tested. |
| `test/incus/mouse_latency_probe.py` | negative | Async connect/read/drain work is deadline-bounded and invalidity is reported. |
| `test/incus/mouse_latency_probe_test.py` | negative | Probe percentiles, phase accounting, and invalidity conditions tested. |
| `test/incus/policy_scheduler_validate.py` | negative | Scheduler policy evidence is checked against expected class semantics. |
| `test/incus/policy_scheduler_validate_test.py` | negative | Scheduler validator pass/fail cases covered. |
| `test/incus/retire_ebpf_artifact_schema.py` | negative | Artifact JSON rejects non-finite/oversized/unknown fields and verifies retired-path evidence. |
| `test/incus/retire_ebpf_artifact_schema_test.py` | negative | Schema, command gate, and required artifact regression coverage present. |
| `test/incus/step1-histogram-classify.py` | negative | Histogram/kick monotonicity and bootstrap classifier preserve evidence invariants. |
| `test/incus/step1-histogram-classify_test.py` | negative | Histogram input and kick delta tests exist; not executed here because `pytest` is unavailable. |
| `test/incus/step1-rate-spread-analysis.py` | negative | Rate parser and trimmed spread report reject inadequate samples. |
| `test/incus/step1-rss-multinomial.py` | negative | RSS expectation simulation keeps exact integer sample accounting. |
| `test/incus/step2-sched-switch-classify.py` | negative | Duty/rank classifier marks drift/inconclusive evidence rather than asserting a false cause. |
| `test/incus/step2-sched-switch-classify_test.py` | negative | Scheduler-switch classifier verdict boundary tests pass. |
| `test/incus/step2-sched-switch-reduce.py` | negative | Event timestamps/buckets/boundaries reject drift and preserve integer delta accounting. |
| `test/incus/step2-sched-switch-reduce_test.py` | negative | Boundary, out-of-order, negative delta, and perf parse coverage pass. |
| `test/incus/step3-tx-kick-classify.py` | negative | Fixed block count, monotonic counters, and integer threshold verdicts checked. |
| `test/incus/step3-tx-kick-classify_test.py` | negative | Classifier tests exist; not executed here because `pytest` is unavailable. |
| `test/incus/test_mouse_latency_shell_test.py` | negative | Shell harness contract checks pass. |

### AF_XDP reproducer sources

Scope: UMEM lifetime, descriptor recycling, XDP program ownership, queue bounds,
and truthfulness of test outcomes. The reproducer sources are not a production
forwarding path. The credible faults found here are all exact matches for prior
reports (predictable `/tmp` BPF object, program restoration, UMEM unmap order,
and descriptor-address recycling), so none is retained.

| Path | Result | Invariant checked |
|---|---|---|
| `test/xsk-repro/libbpf_xsk_shared_test.c` | negative | Shared-UMEM bind, fill/recycle, XDP map lifecycle, and secondary-socket proof reviewed; known root suppressed. |
| `test/xsk-repro/libbpf_xsk_test.c` | negative | RX descriptor ownership, rebind/link-cycle result, and cleanup reviewed; known root suppressed. |
| `test/xsk-repro/main.rs` | negative | Rust UMEM/socket drop order, BPF object handling, XDP restore, and map update failures reviewed; known roots suppressed. |
| `test/xsk-repro/xdp_pass_redirect.c` | negative | Queue-index redirect bounds and PASS fallback reviewed. |

## High-Confidence Findings

### C179-001: Deferred neighbor retransmit omits output-filter reject and log finalization

Source IDs: A1-C001

Title: Deferred neighbor retransmit omits output-filter reject and log finalization

Severity: Medium

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/neighbor_dispatch.rs:315
```rust
            tx_selection_wire_key.as_ref(),
            cos_extra,
            now_ns,
        );
        if cos.drop {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
```

Trace: A packet is buffered for an unresolved neighbor, then the neighbor becomes usable.  The retry recomputes its output-filter selection and forwards any non-drop result; a `reject` result emits neither its reply nor its downgraded event, and a log result emits no filter-log event.

Refutation attempt: The immediate forwarding path consumes reject-reply and log fields before enqueue.  The retry has no shared terminal-action finalizer after selection; its sole terminal check is `cos.drop`.

HPC/invariant check: Neighbor deferral may delay a forwarding decision, but it must not change an output filter's terminal action or observability.

Why it matters: A policy configured to reject or audit traffic silently forwards it after neighbor resolution.

Fix direction: Route retry selection through the same terminal output-filter action handling as immediate TX before frame rewrite/enqueue.

Labels: dataplane, neighbor, output-filter, observability

Dedup note: Searches: `pending_fill_frames`, `neighbor_dispatch`, `output filter reject`, `filter log` in the prior corpus.  #3608 concerns immediate prebuilt output-filter semantics; this root cause is deferred-retry finalization.

### C179-002: GRE decapsulation treats a non-first inner fragment payload as an L4 header

Source IDs: A1-C002

Title: GRE decapsulation treats a non-first inner fragment payload as an L4 header

Severity: Medium

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/gre.rs:519
```rust
            let protocol = packet[9];
            let l4_offset = ihl as u16;
            let payload_offset = match protocol {
                PROTO_TCP => {
                    if packet.len() < ihl + 20 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[ihl + 12] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < ihl + tcp_len {
```

Trace: A valid IPv4 fragment with nonzero offset, or IPv6 fragment with a nonzero Fragment offset, reaches GRE decapsulation.  Its IP protocol still names TCP/UDP, but its first payload byte is continuation data.  The parser interprets that continuation as transport header data and rejects or misclassifies the decapsulated packet.

Refutation attempt: I checked the existing short-L4 protection and #2376.  They reject malformed claimed L4 frames; neither carries a non-first-fragment result through the GRE inner parser.

HPC/invariant check: A non-first fragment has no L4 header at its payload start.  Decapsulation must either preserve it as L3-only or deliberately use fragment association, never parse it as transport.

Why it matters: Valid tunneled fragmented traffic fails despite a valid outer GRE packet.

Fix direction: Return fragment state from both inner parsers and skip L4 parsing/validation for all non-first fragments.

Labels: dataplane, GRE, IPv4, IPv6, fragmentation

Dedup note: Searches: `GRE decap fragment`, `inner L4`, `#2376`.  #2376 is a short-payload bounds issue; this is incorrect parsing of a valid fragment continuation.

### C179-003: Fragmented NDP Neighbor Advertisements are accepted for neighbor learning

Source IDs: A1-C003

Title: Fragmented NDP Neighbor Advertisements are accepted for neighbor learning

Severity: Low

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/parser.rs:218
```rust
    // Walk the IPv6 extension-header chain (shared #2148 engine) to find
    // the real L4 offset + terminal protocol. The walker operates on the
    // L3-relative slice; translate its relative offset back to a
    // frame-absolute offset.
    let l3_slice = raw_frame.get(l3_start..)?;
    let (rel_l4, protocol) =
        super::frame::packet_rel_l4_offset_and_protocol(l3_slice, libc::AF_INET6 as u8)?;
    let l4_start = l3_start.checked_add(rel_l4)?;
    if protocol != NEXT_HEADER_ICMPV6
```

Trace: An on-link IPv6 NA with hop limit 255 and a valid target-link-layer option includes a Fragment Header.  The parser accepts the message and the poll stage learns `(ifindex, target) -> MAC` despite the fragmented NDP form.

Refutation attempt: The NA parser validates RFC 4861 fields such as hop limit, code, target and option shape.  I found no condition carrying fragment-header presence to reject the message.

HPC/invariant check: NDP is a local link-layer control-plane write primitive and must reject fragmented NDP messages (RFC 6980) before learning.

Why it matters: An attacker able to send on-link packets can poison dynamic neighbor state with a form NDP requires receivers to ignore.

Fix direction: Make the IPv6 extension walk report Fragment-header presence and fail `parse_ndp_neighbor_advert` closed when present.

Labels: dataplane, NDP, IPv6, neighbor-security

Dedup note: Searches: `NDP fragment`, `Neighbor Advertisement fragment`, `RFC 6980`.  No prior item has this NDP-learning root cause.

### C179-004: Runtime reset strands legacy shared CoS credits for non-exact queues

Source IDs: A1-C004

Title: Runtime reset strands legacy shared CoS credits for non-exact queues

Severity: High

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/cos/token_bucket.rs:426
```rust
        .flat_map(|(&root_ifindex, root)| {
            root.queues
                .iter()
                .enumerate()
                .filter(|(_, queue)| queue.config.exact && queue.hot.tokens > 0)
                .map(move |(queue_idx, _)| (root_ifindex, queue_idx))
        })
        .collect::<Vec<_>>();
```

Trace: A sharded non-exact queue receives local tokens from the legacy shared lease.  A reset/reconcile calls `release_all_cos_queue_leases`, whose selector excludes that queue; reset clears local runtime state while the reused shared lease retains its outstanding amount.  Subsequent acquisition remains undergranted until refill.

Refutation attempt: Normal completion can return legacy credits.  That does not repair reset, whose all-lease release filter is explicitly `queue.config.exact`.

HPC/invariant check: A reset may discard local banks only after returning every credit to its shared owner; otherwise aggregate accounting and configured-rate availability diverge.

Why it matters: One lifecycle reset can throttle a high-rate, multi-worker CoS class below its configured service rate.

Fix direction: Release outstanding legacy credits for all leased queues during reset, or explicitly retire the shared lease instead of reusing it.

Labels: dataplane, CoS, lifecycle, rate-limiting

Dedup note: Searches: `SharedCoSQueueLease`, `release_all_cos_queue_leases`, `non-exact`, `#4265`, `#4246`.  Those cover lease introduction/exact-v8 giveback; this is the reset-only legacy-credit loss.

### C179-005: Reconcile acknowledges worker and helper spawn failure with phantom lifecycle state

Source IDs: A1-C005

Title: Reconcile acknowledges worker and helper spawn failure with phantom lifecycle state

Severity: High

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:385
```rust
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: failed to start worker thread worker_id={} err={}",
                    worker_id, err
                );
                coord.last_reconcile_stage = format!("spawn_worker_failed:{worker_id}:{err}");
                // #925 Phase 1: the panic slot was inserted before
                // spawn; drop it now so a snapshot reader doesn't
                // see a phantom slot for a worker that never ran.
                coord.worker_panics.remove(&worker_id);
```

Trace: `spawn_supervised_worker` fails synchronously.  The error arm logs and removes only the panic slot, leaving previously inserted `live` and identity records.  The function continues, marks a spawned stage, suppresses helper spawn errors with `.ok()`, and the outer reconcile returns `Ok(())` for persistence/acknowledgement.

Refutation attempt: I checked both worker and auxiliary paths.  The worker error is not propagated; each auxiliary `spawn_supervised_aux(...).ok()` stores stop/channel state whether its thread started or not.

HPC/invariant check: Successful reconciliation requires that published worker/helper lifecycle state correspond to a started resource, or the operation must fail atomically.

Why it matters: Control plane and HA can accept a configuration while traffic workers or neighbor helpers never exist, masking a dataplane outage.

Fix direction: Build state off to the side, propagate all synchronous spawn errors, and publish handles/live/identity/helper state only after successful start.

Labels: control-plane, reconcile, worker-lifecycle, HA

Dedup note: Searches: `spawn_worker_failed`, `spawn_supervised_aux`, `phantom worker`, `#925`.  #925 covers post-start panic reporting, not failure-as-success during bring-up.

### C179-006: Unbound binding status retains stale shared-UMEM and drop counters

Source IDs: A1-C006

Title: Unbound binding status retains stale shared-UMEM and drop counters

Severity: Low

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:266
```rust
fn zero_unbound_slot(binding: &mut BindingStatus) {
    binding.bound = false;
    binding.xsk_registered = false;
    binding.xsk_bind_mode.clear();
    binding.zero_copy = false;
    binding.socket_fd = 0;
    binding.socket_ifindex = 0;
    binding.socket_queue_id = 0;
    binding.socket_bind_flags = 0;
    binding.rx_packets = 0;
```

Trace: A bound slot has nondefault UMEM metadata and martian/IPv6-extension counters.  The slot becomes unbound and is refreshed through `zero_unbound_slot`; it clears generic socket/counter fields but not these copied fields, so status reports attributes/counters from the previous binding.

Refutation attempt: I compared every field copied at lines 49-80 with the zeroing block.  `shared_umem_mode`, group, role, disabled reason, martian and IPv6-extension values have no corresponding clear in this path.

HPC/invariant check: An unbound binding must expose no live-resource identity or live-only counters.

Why it matters: Operators and automation receive false status about socket topology and drops after a binding is removed or crashes.

Fix direction: Centralize copied live-only fields or clear every such field in `zero_unbound_slot`; add a bind-then-unbind status regression test.

Labels: status, binding-lifecycle, observability

Dedup note: Searches: `zero_unbound_slot`, `shared_umem`, `stale binding status`, `#2515`, `#2794`.  Earlier reset/teardown issues do not cover these six omitted status fields.

### C179-007: Failed in-place rewrite mutates aliased UMEM before fallback reuse

Source IDs: A1-C007

Title: Failed in-place rewrite mutates aliased UMEM before fallback reuse

Severity: High

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:411
```rust
                let rewrite_result = apply_rewrite_descriptor(
                    unsafe { &*area },
                    desc,
                    meta,
                    &cached_descriptor,
                    expected_ports,
                )
                .or_else(|| {
                    rewrite_forwarded_frame_in_place(
                        unsafe { &*area },
```

Trace: The fast path retains `packet_frame: &[u8]`, calls a rewrite that obtains mutable UMEM and can alter Ethernet/L3 bytes before later validation returns `None`, then passes the same immutable alias to the generic fallback.  The fallback sees changed bytes; the simultaneous immutable/mutable access violates the documented UMEM aliasing precondition.

Refutation attempt: I traced successful and fallback branches.  The fallback is intentionally reachable on rewrite failure, and no copy/snapshot is made before the in-place rewrite attempt.

HPC/invariant check: A fallible in-place transform must be transactional with respect to both packet bytes and Rust aliasing; failure must leave source bytes usable.

Why it matters: This is memory-safety undefined behavior in the packet worker and can corrupt forwarded packets or cause architecture/compiler-dependent failure.

Fix direction: Validate fully before mutable access, or rewrite a private copy and commit only on success; do not retain an immutable UMEM alias across mutation.

Labels: dataplane, Rust-safety, UMEM, flow-cache

Dedup note: Searches: `slice_mut_unchecked`, `aliased UMEM`, `rewrite fallback`, `#4041`.  #4041 concerns recycle ownership, not mutation through an active immutable alias.

### C179-008: TCP segmentation promotes bytes beyond the IP-declared datagram into payload

Source IDs: A1-C008

Title: TCP segmentation promotes bytes beyond the IP-declared datagram into payload

Severity: High

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/frame/tcp_segmentation.rs:70
```rust
    let Some(l3) = frame_l3_offset(frame) else {
        return None;
    };
    if l3 >= frame.len() {
        return None;
    }
    let payload = &frame[l3..];
    if payload.len() <= mtu {
        return None;
```

Trace: A valid TCP datagram has Ethernet padding or trailing bytes in the AF_XDP descriptor.  Segmentation starts at `l3` and treats all remaining physical bytes as IP payload, produces segments and checksums from that range, and therefore emits bytes the sender did not declare in the IP total/payload length.

Refutation attempt: The normal forwarding builders use declared L3 length for their boundary.  This segmentation function neither reads IPv4 total length nor IPv6 payload length and has no preceding trim on its direct TX call path.

HPC/invariant check: Every packet transformation must preserve the IP-declared datagram boundary; descriptor capacity/tail is not protocol payload.

Why it matters: Packets can be lengthened and application data/protocol state corrupted on transmission.

Fix direction: Parse and validate declared L3 length once, slice segmentation input to that boundary, and reject inconsistent/truncated headers.

Labels: dataplane, TCP, segmentation, packet-integrity

Dedup note: Searches: `tcp segmentation declared length`, `ethernet padding`, `trailing bytes`, `#2361`.  #2361 is an L4 parser-boundary issue, not emitted segmentation payload expansion.

### C179-009: First fragments enter segmentation and L4 recompute paths that require a complete datagram

Source IDs: A1-C009

Title: First fragments enter segmentation and L4 recompute paths that require a complete datagram

Severity: Medium

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/tx/dispatch/mod.rs:1474
```rust
    // a non-first fragment of a TCP datagram (the shim reads the protocol
    // from the IP header / v6 fragment next-header), so without this gate
    // a large non-first fragment would enter the segmentation builders,
    // which parse payload bytes as a TCP header and run NAT/checksum at
    // the fake offset. Route it to the normal forwarding path instead.
    if is_non_first_fragment(&frame[l3..], meta.addr_family) {
        return false;
    }
    frame.len().saturating_sub(l3) > mtu
```

Trace: An IPv4 MF fragment or IPv6 Fragment-header packet with offset zero contains only the first portion of TCP.  It is not non-first, passes the segmentation gate, and code that copies/renumbers TCP payload or recomputes L4 checksums treats the partial datagram as complete.

Refutation attempt: The non-first guard correctly prevents parsing a continuation as TCP, but it is insufficient for transforms that require the entire TCP byte stream.  I found no `is_any_fragment` gate in the segmentation or relevant L4-recompute entries.

HPC/invariant check: L4-complete transformations may run only on unfragmented datagrams; first fragments have a header but not a complete checksum/payload domain.

Why it matters: Fragment forwarding can become overlapping/resegmented traffic with invalid transport semantics.

Fix direction: Use a real-fragment predicate (offset nonzero or more-fragments set) to bypass segmentation and full L4 recomputation unless reassembly/association is available.

Labels: dataplane, fragmentation, TCP, tunnel

Dedup note: Searches: `is_non_first_fragment`, `is_any_fragment`, `first fragment segmentation`.  This is distinct from A1-C008: a valid partial first fragment versus bytes beyond a declared datagram.

### C179-010: NAT-reversed ICMP errors bypass forwarded TTL and hop-limit semantics

Source IDs: A1-C010

Title: NAT-reversed ICMP errors bypass forwarded TTL and hop-limit semantics

Severity: Medium

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/icmp_embed/builders.rs:160
```rust
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let icmp_data = pkt.get(icmp_offset..)?;
    let icmp_csum = checksum16(icmp_data);
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp_csum.to_be_bytes());

    pkt.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let ip_header = pkt.get(..ihl)?;
    let ip_csum = checksum16(ip_header);
```

Trace: A reverse-NAT ICMP error is rebuilt and wrapped as `PendingForwardFrame::Prebuilt`.  The builder recomputes checksums but does not inspect/decrement IPv4 TTL or IPv6 hop limit; TX sends a prebuilt frame without the generic forwarded rewrite, so TTL=1 transits instead of producing Time Exceeded.

Refutation attempt: I checked the standard forwarding path, which performs the TTL/hop-limit decision before normal frame construction.  Prebuilt ICMP error dispatch bypasses that path and the builder has no equivalent field handling.

HPC/invariant check: NAT reversal changes addressing, not router semantics.  Every forwarded IP packet must decrement hop count exactly once and expire at zero.

Why it matters: The router violates loop prevention and can forward packets that should be locally expired.

Fix direction: Apply the shared forwarding hop-limit decision before accepting a prebuilt reverse ICMP error, with the normal Time Exceeded behavior.

Labels: dataplane, NAT, ICMP, routing

Dedup note: Searches: `nat reversed ICMP TTL`, `Prebuilt`, `hop limit`, `#2472`, `#3112`.  Prior issues cover rate-limit/field reversal behavior, not forwarding hop semantics.

### C179-011: Flowless TX traffic bypasses every egress output filter

Source IDs: A1-C011

Title: Flowless TX traffic bypasses every egress output filter

Severity: High

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/tx/cos_classify.rs:462
```rust
        return CoSTxSelection {
            queue_id,
            dscp_rewrite,
            drop: false,
            reject: false,
            filter_log: None,
        };
    };
    // `is_v6` derived above from the (post-NAT) egress key, not `meta` (#3642).
    let has_output_tx_eval = crate::filter::interface_output_filter_needs_tx_eval(
```

Trace: A non-first fragment or a non-query ICMP control packet has no session flow key.  Classification takes the flowless return before the later output-filter evaluation, even though `TermMatchExtra` can evaluate unconditional, address, protocol, or `is-fragment` terms without L4 ports.

Refutation attempt: The existing flowless regression proves port-dependent terms are not spuriously matched.  It does not exercise an L3-only or unconditional output deny, and the early return makes all such terms unreachable.

HPC/invariant check: Missing L4 context must make only L4-dependent predicates fail closed; it must not disable the entire output filter.

Why it matters: A configured egress deny can be bypassed with fragmented or flowless traffic.

Fix direction: Evaluate the output filter on the flowless path using frame-derived `TermMatchExtra`, making unavailable L4 predicates non-matches.

Labels: dataplane, output-filter, fragmentation, policy

Dedup note: Searches: `flowless output filter`, `cos_classify`, `#3291`, `#3608`.  This is a TX classifier reachability bug, distinct from the deferred action-loss defect in A1-C001.

### C179-012: Lossless HA session retries can stall a packet worker past heartbeat expiry

Source IDs: A1-C012

Title: Lossless HA session retries can stall a packet worker past heartbeat expiry

Severity: High

Confidence: High

Evidence: Source: userspace-dp/src/event_stream/mod.rs:648
```rust
                        return Err(format!(
                            "event stream disconnected while queuing seq {reported_seq}"
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "timed out queuing event stream frame seq {reported_seq}"
                        ));
                    }
                    thread::sleep(LOSSLESS_QUEUE_RETRY_DELAY);
```

Trace: A connected peer stops reading, so its output channel is full but not disconnected.  `push_delta_lossless` runs from the worker session-delta flush and repeatedly sleeps until its five-second deadline; that exceeds the same five-second stale heartbeat interval and can trigger watchdog recovery/failover while traffic processing is blocked.

Refutation attempt: The channel retry is bounded, and disconnected peers return promptly.  Neither property handles the connected-but-unread peer; the retry loop deliberately sleeps on that state.

HPC/invariant check: Packet-worker publication must be nonblocking or bounded below watchdog scheduling tolerance.  Control-plane durability cannot monopolize a polling worker.

Why it matters: A slow HA/event consumer can create false liveness loss and a dataplane outage or failover storm.

Fix direction: Move lossless retry to a dedicated exporter, or enqueue bounded retry work and make worker-side send nonblocking with explicit loss/resync state.

Labels: dataplane, HA, event-stream, liveness

Dedup note: Searches: `lossless queue retry`, `heartbeat stale`, `event stream full`, `#2381`, `#2874`.  Existing items discuss buffering/loss correction; this is worker-thread sleep beyond liveness deadline.

### C179-013: RT_FLOW decodes IPv4 NAT64 translations using the original IPv6 family

Source IDs: A1-C013

Title: RT_FLOW decodes IPv4 NAT64 translations using the original IPv6 family

Severity: Medium

Confidence: High

Evidence: Source: userspace-dp/src/event_stream/codec/decode.rs:67
```rust
        timestamp_ns: u64::from_le_bytes(payload[0..8].try_into().ok()?),
        src_ip: read_ip_16(&payload[8..24], wire_af)?,
        dst_ip: read_ip_16(&payload[24..40], wire_af)?,
        nat_src_ip: read_nonzero_ip_16(&payload[72..88], wire_af),
        nat_dst_ip: read_nonzero_ip_16(&payload[88..104], wire_af),
```

Trace: A NAT64 forward session has an IPv6 original tuple and IPv4 rewritten NAT addresses.  Encoding sets the sole family byte from the original source, writes all addresses in generic 16-byte slots, and decode passes the original IPv6 family to the NAT slots, rendering the IPv4 address as an IPv6 value.

Refutation attempt: The payload uses fixed 16-byte slots, which preserves bytes but provides no per-NAT-field family.  I found no NAT64 exception, alternate tag, or decode inference for these fields.

HPC/invariant check: Telemetry must preserve the address family of each address field, especially at cross-family translation boundaries.

Why it matters: RT_FLOW records misidentify NAT64 endpoints, breaking audit correlation and operational debugging.

Fix direction: Carry per-address family/tagging or encode NAT translation family explicitly; add NAT64 open/close round-trip tests.

Labels: event-stream, NAT64, telemetry, protocol

Dedup note: Searches: `RT_FLOW NAT64 family`, `read_nonzero_ip_16`, `nat_src_ip`.  No prior corpus entry identifies this wire-format ambiguity.

### C179-014: Divergent fabric publications overwrite fresh links on every worker poll

Source IDs: A1-C014

Title: Divergent fabric publications overwrite fresh links on every worker poll

Severity: Medium

Confidence: High

Evidence: Source: userspace-dp/src/afxdp/worker/loop_body/mod.rs:759
```rust
        // Check if fabric links were updated by the coordinator (e.g. after
        // RG failover when peer MAC was resolved). If so, rebuild the
        // forwarding Arc with the new fabric links so fabric redirect works.
        {
            let live_fabrics = shared_fabrics.load();
            if !live_fabrics.is_empty() && live_fabrics.as_ref() != &forwarding.fabrics {
                let mut updated = (*forwarding).clone();
                updated.fabrics = live_fabrics.as_ref().clone();
                forwarding = Arc::new(updated);
            }
```

Trace: A full snapshot refresh publishes a new forwarding Arc but does not update the independent `ha.fabrics` store.  A worker loads fresh forwarding, observes the old nonempty fabric store differs, clones forwarding and replaces its fabrics with stale entries.  The next fresh forwarding load repeats the overwrite.

Refutation attempt: The dedicated `refresh_fabric_links` method updates both stores.  Ordinary snapshot refresh only stores `ha.forwarding`, leaving the independent worker override stale.

HPC/invariant check: Two published views of one fabric topology must advance atomically or have one authoritative source; workers must not merge stale topology into a newer forwarding generation.

Why it matters: New/changed fabric forwarding links can disappear or incur an allocation on every worker poll.

Fix direction: Publish both stores from every refresh, or remove the parallel store and derive fabric links solely from the forwarding Arc.

Labels: dataplane, fabric, snapshot, performance

Dedup note: Searches: `shared_fabrics`, `snapshot-refresh fabrics`, `fabric overwrite`, `#1188`, `#3766`.  Earlier work covers snapshot identity/refresh scope, not cross-store divergence and worker overwrite.

### C179-015: Deferred or disarmed changed-plan snapshots become accepted baselines without full forwarding validation

Source IDs: A1-C015

Title: Deferred or disarmed changed-plan snapshots become accepted baselines without full forwarding validation

Severity: High

Confidence: High

Evidence: Source: userspace-dp/src/server/handlers/snapshot.rs:200
```rust
        let prev_snapshot = std::mem::replace(&mut guard.snapshot, Some(snapshot));
        let replanned = replan_queues(
            guard.snapshot.as_ref(),
            guard.status.workers,
            &existing_bindings,
        );
        guard.status.bindings = replanned;
        if defer_workers {
            eprintln!(
                "CTRL_REQ: apply_snapshot defer_workers=true — skipping worker spawn (RETH MAC pending)"
```

Trace: A changed snapshot is applied with `defer_workers=true`, or through a disarmed reconcile path.  It is policy-preflighted, stored, replanned and persisted while its full forwarding build/reconcile is skipped.  Build-only failures therefore surface later at arm/reconcile after the invalid snapshot has become the accepted boot/HA baseline.

Refutation attempt: The nondeferred error arm correctly restores prior state if `reconcile_status_bindings` fails.  That protection is not called in the deferred branch; same-plan refresh is a separate, fully built path.

HPC/invariant check: A snapshot may defer worker activation, but acceptance/persistence must still establish the complete forwarding configuration is buildable.

Why it matters: A control-plane success acknowledgement can durably distribute a configuration that cannot activate dataplane forwarding.

Fix direction: Run the fallible forwarding build/preflight before replacing and persisting any changed snapshot; defer only resource activation after validation.

Labels: control-plane, snapshot, validation, HA

Dedup note: Searches: `defer_workers`, `disarmed reconcile`, `accepted baseline`, `#3766`, `#3789`, `#2794`.  These address same-plan refresh, reconcile error handling, or teardown state, not the changed-plan no-build acceptance branch.

### C179-016: Session-delta polling serializes and fsyncs full state while holding ServerState

Source IDs: A1-C016

Title: Session-delta polling serializes and fsyncs full state while holding ServerState

Severity: High

Confidence: High

Evidence: Source: userspace-dp/src/server/helpers.rs:1290
```rust
    let mut guard = state.lock().expect("state poisoned");
    refresh_status(&mut guard);
    let payload = Payload {
        status: &guard.status,
        snapshot: &guard.snapshot,
    };
    let data = serde_json::to_vec_pretty(&payload).map_err(|e| format!("encode state: {e}"))?;
    let mut bytes = data;
    bytes.push(b'\n');
    guard
```

Trace: The fallback delta poll runs repeatedly.  Each nonempty request sets `persist_state`; the handler still holds the `ServerState` guard while refreshing/pretty-serializing the entire state and waiting for the writer request.  The writer's durability contract includes file and parent-directory fsync, so storage latency blocks all contending control operations.

Refutation attempt: The writer runs on another thread, but `persist` waits for its response.  The handoff does not shorten the critical section, and no coalescing/dirty-generation gate avoids complete snapshots on successive delta polls.

HPC/invariant check: Incremental session delta handling must not hold the global state lock across full serialization and synchronous durable I/O.

Why it matters: High session churn turns a cheap poll into lock convoying, delaying snapshots, status, and HA/control operations.

Fix direction: Mark durable state dirty under lock, snapshot/serialize outside it, and coalesce asynchronous persistence by generation.

Labels: control-plane, persistence, locking, performance

Dedup note: Searches: `persist_state`, `write_state`, `ServerState fsync`, `#2962`, `#4054`.  Prior items concern export work/locks, not every delta forcing durable full-state persistence under this lock.

### C179-017: Unbounded snapshot rx_queues drives overflow-prone binding-plan construction

Source IDs: A1-C017

Title: Unbounded snapshot rx_queues drives overflow-prone binding-plan construction

Severity: Medium

Confidence: High

Evidence: Source: userspace-dp/src/server/helpers.rs:1154
```rust
    let queue_count = candidates.iter().map(|(_, rx)| *rx).min().unwrap_or(0);
    let interfaces = candidates
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(queue_count * interfaces.len());
    let mut slot = 0u32;
    for queue_id in 0..queue_count {
        for iface in &interfaces {
            let mut binding = existing_by_slot.remove(&slot).unwrap_or_default();
```

Trace: A peer/control snapshot supplies a very large nonzero `rx_queues`.  The Rust boundary accepts it as `usize`; replan uses it in a multiplied `Vec::with_capacity` and nested binding construction before the full forwarding/reconcile validation path.  The wire-size limit does not bound the numeric value.

Refutation attempt: Normal Go configuration constrains queue counts, but this is an independent Rust trust boundary for HA/mixed-version/corrupt inputs.  I found no checked maximum or checked multiplication before allocation.

HPC/invariant check: Wire-derived counts must be bounded by platform/config maxima and use checked arithmetic before capacity reservation or identifier conversion.

Why it matters: A malformed snapshot can cause allocation failure, panic in debug/overflow contexts, or excessive control-plane work before rejection.

Fix direction: Validate `rx_queues` against a defined maximum at decode/preflight and use `checked_mul` with a bounded allocation plan.

Labels: control-plane, snapshot, resource-exhaustion, validation

Dedup note: Searches: `rx_queues`, `replan_bindings`, `with_capacity`, `queue count`.  Existing queue alias/capacity work does not cover this untrusted count-to-plan allocation boundary.

### C179-018: Malformed non-empty NAT64 sync state silently degrades into ordinary NAT state

Source IDs: A1-C018

Title: Malformed non-empty NAT64 sync state silently degrades into ordinary NAT state

Severity: Medium

Confidence: High

Evidence: Source: userspace-dp/src/server/helpers.rs:393
```rust
    if snat_v4_str.is_empty() {
        return None;
    }
    let snat_v4: std::net::Ipv4Addr = snat_v4_str.parse().ok()?;
    // A NAT64 forward session is keyed on the original IPv6 5-tuple.
    let (std::net::IpAddr::V6(orig_src_v6), std::net::IpAddr::V6(orig_dst_v6)) =
        (key.src_ip, key.dst_ip)
    else {
        return None;
    };
```

Trace: A synchronized NAT64 session carries a nonempty malformed pool source, or an incompatible original family.  Rebuild returns `None` through `.ok()?`; the caller treats `None` as absence of NAT64 and installs an ordinary session rather than rejecting the malformed nonempty representation.

Refutation attempt: Empty is intentionally backward-compatible absence.  The same `None` result is used for malformed and wrong-family nonempty inputs, so the caller cannot distinguish absence from corruption.

HPC/invariant check: Optional fields may default only when absent.  A present discriminator/value that fails validation must fail the record closed.

Why it matters: HA can install a semantically different session after receiving corrupted NAT64 state, leading to incorrect reverse forwarding.

Fix direction: Return `Result<Option<_>, Error>` and propagate errors for nonempty malformed/incompatible NAT64 state while retaining empty-as-legacy behavior.

Labels: HA, NAT64, session-sync, validation

Dedup note: Searches: `build_nat64_reverse_rebuild`, `nat64_snat_v4`, `malformed sync`.  #4565 introduces reverse-BIB synchronization; this is its malformed-present decode boundary.

### C179-020: Authoritative neighbor replacement commits a valid subset of a malformed snapshot

Source IDs: A1-C020

Title: Authoritative neighbor replacement commits a valid subset of a malformed snapshot

Severity: Low

Confidence: High

Evidence: Source: userspace-dp/src/server/handlers/neighbors.rs:23
```rust
        };
        let Some(mac) = afxdp::parse_mac_str(&neigh.mac) else {
            continue;
        };
        if !afxdp::neighbor_state_usable_str(&neigh.state) {
            continue;
        }
        resolved.push((neigh.ifindex, ip, afxdp::NeighborEntry { mac }));
    }
    guard.afxdp.apply_manager_neighbors(replace, &resolved);
```

Trace: An authoritative replacement includes valid rows and one malformed row.  The handler drops the malformed row, calls replace with the valid subset, and coordinator removes all prior manager-owned neighbors before inserting only that subset.  An all-invalid replacement can clear the set entirely.

Refutation attempt: Partial parsing is appropriate only for incremental/best-effort updates.  The request is explicitly a replacement, and no error or all-or-nothing validation gate exists before deletion.

HPC/invariant check: An authoritative snapshot update must be atomic: either every row validates and replaces the old set, or the old set remains intact.

Why it matters: A single malformed neighbor entry can silently delete unrelated configured next-hop resolution and blackhole traffic.

Fix direction: Validate all rows first and return an error on any malformed entry before applying a replace; keep lenient behavior only for explicitly incremental APIs.

Labels: control-plane, neighbor, atomicity, validation

Dedup note: Searches: `apply_manager_neighbors`, `replace neighbors malformed`, `neighbor subset`.  No prior corpus item covers replacement atomicity for this API.

### C179-021: Remote session limit wraps past int32 and silently becomes the default

Source IDs: A10-C001

Title: Remote session limit wraps past int32 and silently becomes the default

Severity: Low

Confidence: High

Evidence: `cmd/cli/show_flow.go:127` validates only positivity before narrowing the host `int` into the protobuf's `int32` field.

```go
		case "limit":
			v, err := takeValue(&i, "limit")
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("invalid limit %q", v)
			}
			p.req.Limit = int32(n)
```

Trace: On the appliance's 64-bit build, `show security flow session limit 2147483648` passes `strconv.Atoi`. Converting it to `int32` yields `-2147483648`. The request leaves `PageSize` at zero, so `GetSessions` selects `getSessionsLegacy`; `pkg/grpcapi/server_sessions.go:590-595` replaces every non-positive limit with 100 and returns success. The operator therefore receives 100 rows rather than an input error.

Refutation attempt: The parser rejects non-numeric and non-positive source text, but it does not reject values above `MaxInt32`. The server caps large positive limits at 10,000 but treats the wrapped negative value as the default, and its central validation checks only negative `Offset`. A 32-bit build would reject the value in `Atoi`, but the target build is 64-bit and reaches the narrowing conversion.

HPC/invariant check: No packet-path work is involved. A CLI quantity must either retain its requested value across RPC serialization or fail before narrowing.

Why it matters: Incident-response automation can receive a successful, truncated session view after asking for a materially different limit, hiding sessions without any diagnostic.

Fix direction: Parse with `strconv.ParseInt(v, 10, 32)`, reject `ErrRange`, and add `MaxInt32+1` coverage. Prefer also enforcing the documented 10,000 server ceiling in the client so oversized requests fail explicitly rather than clamp.

Labels: cli, correctness, input-validation, session-observability

Dedup note: I searched `dedup-index.txt` for `show session limit`, `GetSessions limit`, `int32`, `overflow`, `wrap`, `Atoi`, and `default limit`. The corpus's rollback-index narrowing item and #4868 concern different parsers and mutating commit/rollback operations; neither covers the session request's wrap-to-default behavior.

### C179-022: Detailed security statistics suppress a failed buffer-detail RPC

Source IDs: A10-C002

Title: Detailed security statistics suppress a failed buffer-detail RPC

Severity: Low

Confidence: High

Evidence: `cmd/cli/show_security.go:632` requests the buffer section for `show security statistics detail`, prints it only on success, and returns nil regardless of the RPC error.

```go
	text, err := c.client.ShowText(c.ctx(), &pb.ShowTextRequest{Topic: "buffers"})
	if err == nil && text.Output != "" {
		fmt.Printf("\n%s", text.Output)
	}
	return nil
```

Trace: `handleShowSecurity` maps `show security statistics detail` to `showStatistics(true)`. After `GetGlobalStats` succeeds and its counters are printed, the function issues `ShowText("buffers")`. If that second RPC fails, the condition skips the section and the function returns nil, so the remote CLI reports success with incomplete detail output.

Refutation attempt: The primary RPC is checked and the separately exposed `show system buffers` path returns its `showText` error, but neither protects this secondary call. Partial output may be worth preserving, yet the code emits neither a warning nor a nonzero result. Local statistics code already warns when late counter reads make a result incomplete, so silent best-effort behavior is not an established display contract.

HPC/invariant check: No packet hot path is affected. A requested diagnostic detail section must be rendered or explicitly reported unavailable.

Why it matters: Buffer pressure and queue exhaustion data can disappear exactly during control-path degradation while scripts and operators see a successful command.

Fix direction: Return a wrapped error after the already-printed counters, or emit an explicit warning and return a failure status when the buffer RPC fails. Add a fake-client regression for a successful global-stat call followed by a failed `ShowText` call.

Labels: cli, observability, error-handling, correctness

Dedup note: I searched for `show statistics partial`, `ShowText buffers`, `GetGlobalStats`, `swallow`, and `buffer RPC`. #3344 covers a server-side per-zone screen-counter read omitted from a different command. This root is the remote client's ignored follow-on RPC at a separate fix locus.

### C179-023: Top-20 session view retains and sorts every matching session

Source IDs: A10-C003

Title: Top-20 session view retains and sorts every matching session

Severity: Medium

Confidence: High

Evidence: `pkg/cli/cli_show_flow.go:786` appends a fully formatted record, including allocated strings, for every matching forward session.

```go
		entries = append(entries, topTalkerEntry{
			src:      fmt.Sprintf("%s:%d", srcIP, ntohs(key.SrcPort)),
			dst:      fmt.Sprintf("%s:%d", dstIP, ntohs(key.DstPort)),
			proto:    protoNameFromNum(key.Protocol),
			zone:     inZone + "->" + outZone,
			state:    sessionStateName(val.State),
			app:      appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID),
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
```

Trace: `show security flow session sort bytes|packets` enters `showTopTalkers`. Both IPv4 and IPv6 iterators append every matching forward entry. Only after both scans does `sort.Slice` order the full slice in O(N log N), and only then do lines 853-865 limit rendering to 20. The runtime advertises capacities such as 786,432 sessions, so one view can retain hundreds of thousands of multi-string entries before producing output.

Refutation attempt: Optional filters can reduce N but are not required. The iterator must scan all sessions to compute a correct top 20, but it need not retain or sort all of them: a fixed-size heap preserves the result with bounded memory and O(N log 20) comparison work. The pager cannot backpressure this path because no output occurs before collection and sorting.

HPC/invariant check: This is control-plane work, but it runs in the daemon-local CLI path while the process owns HA and management duties. A fixed-cardinality operator view should not allocate in proportion to the full session table.

Why it matters: A view-class command on a busy appliance can create large heap, GC, and sort pressure and can stall or OOM the long-lived control process.

Fix direction: Maintain a size-20 min-heap keyed by the selected counter while scanning, retain only those entries, and stably sort the final heap. Add a high-cardinality fake iterator test that asserts both ranking and bounded retained entries.

Labels: cli, sessions, resource-exhaustion, performance, bounded-memory

Dedup note: I searched for `showTopTalkers`, `top talker session memory`, `session sort OOM`, and `top-K heap`. #3099 is a bounded Space-Saving aggregation for security-log reports, not this session-table presenter. It supplies a pattern, not an existing issue for this root.

### C179-024: Brief session rendering buffers both complete scans before pager output

Source IDs: A10-C004

Title: Brief session rendering buffers both complete scans before pager output

Severity: Medium

Confidence: High

Evidence: `pkg/cli/cli_show_flow.go:539` flushes the one brief `tabwriter.Writer` only after the IPv6 iterator has completed.

```go
	if err != nil {
		return fmt.Errorf("iterate sessions_v6: %w", err)
	}

	if briefWriter != nil {
		flushSessionBriefWriter(briefWriter)
	}
```

Trace: The brief branch creates one `text/tabwriter.Writer` before the IPv4 scan and sends every IPv4 and IPv6 row to it. Go's tabwriter writes buffered table data to its underlying writer on `Flush`; this code performs that flush only after both scans. Consequently `dispatchWithPager`'s pipe receives no rows during iteration and the formatted O(N) table remains in the daemon until the end.

Refutation attempt: The non-brief path writes rows directly and the pager itself is explicitly bounded to a screen plus pipe buffering, but the tabwriter sits upstream of that pipe. The one-row formatting test proves layout only. There is no periodic flush, chunk boundary, output cap, or high-cardinality early-output regression.

HPC/invariant check: No forwarding hot path is changed, but this defeats a control-plane backpressure invariant intentionally established by the streaming pager. Formatting must not retain a second full representation of the session table.

Why it matters: A read-only brief view can delay all output and consume a large additional heap at maximum session cardinality, stalling or killing the daemon.

Fix direction: Render fixed-width rows directly to the pager pipe, or flush bounded tabwriter chunks with an explicit alignment tradeoff. Test that output begins before iterator completion and retained formatter state stays bounded.

Labels: cli, sessions, streaming, backpressure, resource-exhaustion

Dedup note: I searched for `SessionBrief`, `tabwriter session`, `brief flow buffer`, `pager`, and `streaming`. No corpus item covers this formatter. A10-C003 has a different trigger and remedy: top-K selection retains structured candidates, while this path receives a stream and buffers it in presentation.

### C179-025: Show-log count buffers unbounded child output ahead of the pager

Source IDs: A10-C005

Title: Show-log count buffers unbounded child output ahead of the pager

Severity: Medium

Confidence: High

Evidence: `pkg/cli/cli_show_system.go:794` resolves an allowed log path, then uses `CombinedOutput` and prints only after the child exits.

```go
			logPath, err := c.resolveShowLogPath(filename)
			if err != nil {
				return err
			}
			out, err := exec.Command("tail", "-n", strconv.Itoa(n), logPath).CombinedOutput()
			if err != nil {
				return fmt.Errorf("read %s: %w", logPath, err)
			}
			fmt.Print(string(out))
			return nil
```

Trace: Any PermView user can run `show log <very-large-count>` or `show log <configured-file> <very-large-count>`. Both parsers preserve any positive host `int`. `journalctl` or `tail` then writes the selected retained history into `CombinedOutput`'s memory buffer; `fmt.Print` reaches the outer pager only after the subprocess completes and the full allocation has occurred.

Refutation attempt: #4860 correctly restricts named files to configured syslog destinations, but authorization does not bound their retained size. Disk/journal retention gives a finite environmental ceiling, not a safe per-command memory ceiling. The journal branch repeats the same pattern, and the pager cannot regulate a child whose stdout is captured internally.

HPC/invariant check: This is a management-plane backpressure invariant. Large read-only output should flow through the existing bounded pager rather than be duplicated in heap.

Why it matters: A low-privilege view command can allocate retained log history at appliance scale and make the management daemon unresponsive or OOM.

Fix direction: Reject or clamp counts above a documented maximum and connect child stdout directly to the command's current output stream so the pager applies backpressure. Keep stderr bounded or separate, and test oversized counts plus output-before-child-exit.

Labels: cli, logging, backpressure, resource-exhaustion, permissions

Dedup note: I searched for `showDaemonLog`, `show log buffer`, `journalctl bound`, `tail CombinedOutput`, and `child output`. #4860 covers path authorization, while #5057 bounds diagnostic child-process concurrency; neither bounds or streams this command's output bytes.

### C179-026: Delimiter-concatenated LLDP identifiers collide in the neighbor map

Source IDs: A10-C006

Title: Delimiter-concatenated LLDP identifiers collide in the neighbor map

Severity: Low

Confidence: High

Evidence: `pkg/lldp/lldp.go:513` stores the parsed opaque identifiers under a slash-concatenated string key.

```go
		if neighbor == nil {
			continue
		}
		neighbor.Interface = iface.Name
		neighbor.LastSeen = time.Now()
		neighbor.ExpiresAt = time.Now().Add(time.Duration(neighbor.TTL) * time.Second)

		key := fmt.Sprintf("%s/%s/%s", iface.Name, neighbor.ChassisID, neighbor.PortID)
		m.learnNeighbor(key, neighbor)
```

Trace: Non-MAC chassis IDs and port IDs are accepted as sanitized opaque TLV strings. `sanitizeTLVString` replaces control runes but preserves `/`. On the same local interface, `(chassis="a/b", port="c")` and `(chassis="a", port="b/c")` both encode as `ifname/a/b/c`. `learnNeighbor` sees the second as an existing key and replaces the first record through its refresh branch.

Refutation attempt: Mandatory-TLV length checks reject empty/truncated identifiers, and the 64-neighbor per-interface cap bounds memory. Neither guard makes the tuple encoding injective. Slash is also a normal character in interface-style port identifiers, and no escaping, length prefix, or structured comparison occurs before the existing-key update.

HPC/invariant check: This is a bounded L2 control table, not packet forwarding. The neighbor identity key must remain one-to-one across every accepted `(interface, chassis, port)` tuple.

Why it matters: An L2-local sender can hide or replace a distinct legitimate neighbor in inventory and `show lldp neighbors`, corrupting topology observability without exceeding the table cap.

Fix direction: Change the map key to a comparable struct containing the three strings, or encode each component with an unambiguous length prefix. Add a receive/learn regression for the two colliding slash-bearing tuples.

Labels: lldp, observability, identity, input-validation

Dedup note: I searched for `LLDP neighbor key`, `chassis port slash`, `delimiter collision`, `overwrite`, #4043, and #4044. #4043 sanitizes terminal/log control characters and #4044 caps distinct entries; neither addresses ambiguous tuple identity.

### C179-027: Non-positive HA roll TTL makes the cross-orchestrator lease immediately reclaimable

Source IDs: A10-C007

Title: Non-positive HA roll TTL makes the cross-orchestrator lease immediately reclaimable

Severity: High

Confidence: High

Evidence: `scripts/deploy/xpf-deploy.py:1110` treats a lease as live only while `now < expires`, then derives the new expiry directly from the caller-supplied integer. Both `--lease-ttl` parsers use unconstrained `type=int` at lines 1800 and 1837.

```python
        "f=/var/lib/xpf/kernel-roll.lease; "
        'if [ -f "$f" ]; then '
        'exp=$(sed -n \'s/.*"expires_at": *"\\([^"]*\\)".*/\\1/p\' "$f"); '
        'now=$(date -u +%%s); ee=$(date -u -d "$exp" +%%s 2>/dev/null || echo 0); '
        # live lease held by someone else -> do NOT touch it; fail to acquire.
        'if [ "$now" -lt "$ee" ]; then exit 1; fi; '
        'fi; '
        "exp=$(date -u -d \"+%d seconds\" +%%Y-%%m-%%dT%%H:%%M:%%SZ); "
        "umask 022; "
```

Trace: An operator or automation invokes `kernel-roll` or `image-roll` with `--lease-ttl 0`; argparse accepts it. `_acquire_lease` writes an expiry at the current second, so the next acquisition's strict `now < ee` check treats it as expired. A second driver can take each short-lived per-node flock after the first command releases it, overwrite both leases, and proceed because the first driver never rechecks ownership. The two drivers can then pass their peer-ready prechecks before either drain changes HA state and drain opposite nodes, creating a no-primary forwarding outage.

Refutation attempt: The per-node flock correctly serializes each read/replace/write transaction, but it is released immediately after acquisition and is not the roll-duration lock. Canonical node ordering prevents acquisition deadlock only. Holder-guarded release prevents deleting a successor's lease but does not stop the displaced holder. `DrainAndConfirm` verifies the peer can take traffic at that instant; two independent drivers can both satisfy that predicate before either demotion. The positive default of 1800 seconds does not protect an explicitly accepted zero, and no deploy test rejects non-positive TTLs.

HPC/invariant check: No packet hot path is involved. The HA invariant is that exactly one orchestrator owns both node reservations from before the first drain through rejoin or guarded failure recovery.

Why it matters: A single zero-valued automation parameter removes the only cross-orchestrator fence and allows concurrent maintenance to demote both HA nodes, interrupting all redundancy groups.

Fix direction: Use one shared argparse positive-integer type for both roll commands and reject zero/negative values before any remote action. Define a defensible minimum or add lease renewal/ownership checks for long rolls, and add parser plus two-driver contention regressions.

Labels: ha, upgrade-safety, deploy, cli-validation, fail-open

Dedup note: I searched for `lease TTL`, `kernel-roll lease`, `image-roll lease`, `zero lease`, `negative lease`, `expired lease`, and `cross orchestrator`. The prior codex-review-175 item concerns a syntactically empty persisted lease in local self-recovery; #1930 records the lease implementation and mutex intent. Neither covers a caller-supplied non-positive TTL invalidating the writer's own reservation.

### C179-028: NPTv6 drops rule-set scope, globally applies ingress mappings, and rejects multi-scope hydration

Source IDs: A2-C001

Title: NPTv6 drops rule-set scope, globally applies ingress mappings, and rejects multi-scope hydration

Severity: High

Confidence: High

Evidence: `pkg/dataplane/userspace/nat_nptv6.go:20-25` serializes `FromZone`; `userspace-dp/src/protocol/nat.rs:361-368` carries it on the wire; `userspace-dp/src/nptv6.rs:292-300` constructs the runtime rule without it; `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1502-1520,1590-1600` resolves ingress scope but does not pass it to NPTv6.

```rust
            let rule = Nptv6Rule {
                internal_prefix,
                external_prefix,
                adjustment,
                prefix_words: iwords,
            };

            // Inbound: match external prefix on dst, rewrite to internal.
            state.inbound.push(rule.clone());
```

Trace: `compileNATStatic` scope-expands a static-NAT rule-set once per `from` scope (`pkg/config/compiler_nat.go:2567-2575`), and the Go snapshot builder emits one NPTv6 snapshot per expansion with that scope. `Nptv6State::try_from_snapshots` discards the field, compares all external/internal prefixes in global seen lists, and errors on the second identical expansion (`userspace-dp/src/nptv6.rs:223-303`). At runtime the inbound path has an `ingress_zone_name`, but invokes `translate_inbound(&mut dst_v6)` with only the address. A packet in another zone with the external prefix therefore translates before routing/policy selection. The #4339-valid multi-scope configuration instead reaches the helper as duplicate global prefixes and makes the forwarding rebuild retain its prior state.

Refutation attempt: I checked the wire DTO, builder, hydrate path, NPTv6 APIs, both outbound call sites, and the embedded-ICMP caller. There is no caller-side scope filter or state partition: the APIs accept only an address and `Nptv6Rule` has no scope member. The ingress-zone lookup immediately preceding the NPTv6 call serves DNAT/static NAT only. I do not rely on an assumed outbound zone semantic for this finding; the unscoped inbound rewrite and #4339 hydration contradiction independently reproduce the defect.

HPC/invariant check: The configured ingress scope is a translation identity. Resolve it once into the forwarding state and key/partition NPTv6 rules by stable zone ID; matching then adds only a bounded integer comparison on the first-flow path, with no allocation, lock, or logging.

Why it matters: A mapping configured for one external zone can translate matching traffic from another zone, defeating the rule-set boundary. A successful multi-scope commit can also leave the old NPTv6 forwarding state live because the helper rejects its duplicate expansions.

Fix direction: Preserve the effective `from` scope in `Nptv6Rule`, make inbound matching take the resolved ingress scope, and partition overlap detection by that scope while coalescing exact copies of one logical multi-scope rule. Define and test the reverse/outbound scope contract explicitly rather than retaining the current global address-only API. Add wrong-zone, same-prefix/different-zone, #4339 multi-scope hydrate, and embedded-ICMP regressions.

Labels: bug, nptv6, zone-scope, security-boundary, config-runtime-drift

Dedup note: Searched the corpus with `rg -n -i 'nptv6.{0,120}(zone|scope|from)|(?:zone|scope|from).{0,120}nptv6|#4339|Nptv6RuleSnapshot|translate_inbound|translate_outbound'`. #2241 is the global first-match overlap invariant and #4339 suppresses a Go validator's self-comparison; neither preserves scope in the Rust rule or runtime matcher. This is a scope-loss root cause, not a duplicate overlap-validator finding.

### C179-029: HA import does not reserve an address-only source-NAT reverse identity

Source IDs: A2-C002

Title: HA import does not reserve an address-only source-NAT reverse identity

Severity: High

Confidence: High

Evidence: `userspace-dp/src/nat/source.rs:809-879` makes reservation conditional on a translated port, while local address-only flows mint the full reverse-identity token at `userspace-dp/src/nat/source.rs:1303-1330` and `1392-1413`.

```rust
    if is_reverse {
        return;
    }
    let Some(rewrite_src) = nat.rewrite_src else {
        return;
    };
    let Some(rewrite_src_port) = nat.rewrite_src_port else {
        return;
    };
```

Trace: A real `port no-translation` or port-less pool flow invokes `reserve_address_only`, which records both `live_by_flow` and `address_only_owners` keyed by protocol, pool address, preserved source port, and remote endpoint (`userspace-dp/src/nat/allocator.rs:1589-1655`). Its `NatDecision` intentionally has `rewrite_src_port: None`. HA upsert calls `reserve_synced_source_nat_allocation` for a peer-synced forward entry (`userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:82-94`), but the shown guard returns before creating either address-only owner record. After takeover, a local flow can claim the same identity because the imported session is absent from the allocator. The reverse session index retains colliding handles, but returns the first that matches the identical wire tuple (`userspace-dp/src/session/lookup.rs:215-243`), so it cannot demultiplex two indistinguishable address-only flows.

Refutation attempt: I traced every reservation and release caller, including delete-sync and stale-session teardown. `release_source_nat_allocation` deliberately reconstructs the preserved port from `key.src_port` when `rewrite_src_port` is absent (`userspace-dp/src/nat/source.rs:761-806`), proving a synced address-only reservation has sufficient data and shares the existing release path. #4399's 1:N reverse index prevents displacement but explicitly selects the first valid candidate for an identical tuple; it is not a uniqueness guarantee. The issue occurs with identical configuration on healthy peers, not only under configuration drift.

HPC/invariant check: This is a cold peer-install operation. One mutex-protected address-only owner insertion per imported forward session preserves the existing per-packet uniqueness invariant without adding hot-path work.

Why it matters: A failover can admit a fresh flow with the same public reverse identity as an active peer-synced flow. Replies then have no unique internal owner, creating misdelivery and session-integrity exposure.

Fix direction: Add an idempotent synced-address-only reservation that derives the preserved port from the session key, verifies the translated pool address belongs to the local rule, and inserts the same `live_by_flow` plus `address_only_owners` state as `reserve_address_only` without advancing the address cursor. Cover TCP no-translation, GRE/ESP-style port-less flows, collision, delete/reap release, and active-to-standby promotion.

Labels: bug, snat, cgnat, ha, failover, allocator, session-integrity

Dedup note: Searched with `rg -n -i 'address.?only|no.?translation.{0,120}(ha|sync|reserve|failover|collision)|(?:ha|sync|reserve|failover|collision).{0,120}(address.?only|no.?translation)|#5269|#4388|reserve_synced_source_nat_allocation'`. #4388 reserves a PAT `(pool_addr, translated_port)` occupancy bit and its record expressly excludes address-only sessions; #5269 added a separate full reverse-identity owner map. The missing HA import of that later, distinct token is not the #4388 port-reservation root cause.

### C179-030: Address-only source NAT falsely exhausts a multi-address non-persistent pool

Source IDs: A2-C003

Title: Address-only source NAT falsely exhausts a multi-address non-persistent pool

Severity: Medium

Confidence: High

Evidence: `userspace-dp/src/nat/source.rs:1268-1330` selects one address and returns the first reservation failure; the IPv6 branch has the same shape at `1359-1413`.

```rust
                if address_only {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        0,
                        rule.pool_addresses_v4.len(),
                        rule.address_persistent,
                    );
                    let pool_addr = rule.pool_addresses_v4[addr_idx];
                    if tuple_unknown {
```

Trace: With `address_persistent == false`, `address_index` advances a round-robin counter and chooses one address (`userspace-dp/src/nat/allocator.rs:851-871`). The caller invokes `reserve_address_only` once and immediately returns `AllocatorExhausted` on a collision. For a two-address pool, flow A can own reverse identity K on address A, an unrelated flow can advance the cursor through B and then release it, and a second K flow can wrap to A. It is denied despite B being free and producing a distinct reverse identity. In contrast, PAT `allocate_translation` starts at the same selected address but probes every family member when addresses are non-persistent (`userspace-dp/src/nat/allocator.rs:939-952`).

Refutation attempt: Address-persistent selection is intentionally single-address, but the reproduced branch has it disabled. `reserve_address_only` is idempotent only for the exact same forward key and has no cross-address retry; no outer caller retries it. The #5269 two-address test proves only the fortunate A-then-B cursor order, not occupied-start/free-next. Choosing B is safe because translated IP is part of `AddressOnlyReverseKey`.

HPC/invariant check: This remains first-flow allocation. Start at the existing round-robin result and inspect further configured addresses only after an owner collision; normal first-address success keeps the present one lock acquisition. Preserve the one-address behavior for address-persistent rules.

Why it matters: Partially available address-only pools intermittently report `source_nat_pool_exhausted` and drop new TCP, UDP, GRE, or ESP flows based on unrelated allocation/release order.

Fix direction: Implement a bounded address-only allocation helper that follows the PAT start-index and non-persistent family probe policy, claiming the first free reverse identity. Add IPv4/IPv6 occupied-first/free-next, all-occupied, sticky address-persistent, release/reuse, and concurrent-contender tests.

Labels: bug, snat, cgnat, allocator, false-exhaustion, availability

Dedup note: Searched with `rg -n -i '#3047|single collision|forward.probe|spurious.*exhaust|false.*exhaust|address_attempts|family_len|address[_ -]only'`. #3047 probes alternate ports within one PAT address after a bitmap collision; it neither allocates address-only identities nor probes a second pool address. #5269 establishes the owner-map invariant but has no all-address availability probe. The root cause and fix locus are distinct.

### C179-031: NAT64 strict commit validation accepts a prefix grammar the runtime drops

Source IDs: A2-C004, A3-C006

Title: NAT64 strict commit validation accepts a prefix grammar the runtime drops

Severity: Medium

Confidence: High

Evidence: `pkg/config/compiler_nat.go:791-804` accepts `64:ff9b::/96/garbage`, while `userspace-dp/src/nat64.rs:742-758` requires exactly two slash-separated parts and skips it.

```go
		parts := strings.Split(rs.Prefix, "/")
		// The token after the first '/' must parse as a decimal /96. A missing
		// mask (no '/'), an empty mask, a non-numeric mask, or any length other
		// than 96 is rejected — only /96 is supported by the translator.
		mask96 := false
		if len(parts) >= 2 {
			if m, err := strconv.ParseUint(parts[1], 10, 8); err == nil && m == 96 {
				mask96 = true
			}
		}
```

Trace: The strict compiler reaches `validateNAT64PrefixStrict` from the tail gates (`pkg/config/compiler_tailgates.go:141-155`) and accepts an extra-slash value because its first two tokens are valid. `buildNAT64Snapshots` copies the original string unchanged (`pkg/dataplane/userspace/nat64.go:79-120`). Rust splits it into three parts, logs, and skips that rule; `extra_slash_prefix_skips_rule` documents the exact runtime behavior (`userspace-dp/src/nat64_tests.rs:346-379`). If this was the only matching rule, `Nat64State::classify_ipv6_dest` returns `NoPrefixMatch`, and the forwarding path continues ordinary IPv6 routing (`userspace-dp/src/nat64.rs:886-911`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1621-1646`). Cross-area review independently confirmed that A3-C006 follows this same validator-to-runtime path and requires the same exact-arity repair; it adds no separate failure mode.

Refutation attempt: I checked schema ingestion, strict validation, snapshot construction, loader behavior, classification, and the existing Go/Rust tests. The schema treats the malformed value as one scalar, so it does not normalize or reject it before the validator. The validator's own comment incorrectly claims trailing components are ignored by both sides; Rust's explicit exact-length test proves otherwise. The fail-scoped loader avoids freezing the whole forwarding rebuild, but it does not make a commit-successfully omitted NAT64 mapping correct.

HPC/invariant check: Exact grammar validation is constant work at commit time and leaves the packet path unchanged.

Why it matters: The control plane reports a successful NAT64 configuration while the dataplane silently omits the affected mapping. Matching synthetic destinations can lose translation, blackhole, or follow an IPv6 route.

Fix direction: Require `len(parts) == 2` before parsing the mask, correct the stale Go comment and lenient-path wording, and add strict and lenient extra-slash tests plus a compile-to-snapshot-to-Rust fixture corpus for valid and malformed forms.

Labels: bug, nat64, config-validation, contract-drift, availability

Dedup note: Searched with `rg -n -i 'nat64.{0,120}(prefix|slash|malformed|grammar|validator|loader)|(?:prefix|slash|malformed|grammar|validator|loader).{0,120}nat64|#3886|#3888|extra.?slash|trailing.{0,80}(garbage|slash)'`. #3886 introduced the /96 gate and #3888 made Rust reject an extra slash in fail-scoped loading; neither fixes the remaining Go `len(parts) >= 2` acceptance. This is the control-plane grammar drift left after the runtime hardening.

### C179-032: Disabled AppID tuple fallback performs per-session full application scans

Source IDs: A3-C001

Title: Disabled AppID tuple fallback performs per-session full application scans

Severity: Medium

Confidence: High

Evidence: `pkg/appid/runtime.go:208`
```go
		best := ""
		bestPortBased := false
		for name, app := range cfg.Applications.Applications {
			// #4865: skip a tolerated nil user-application value (a JSON null
			// decoding to a nil pointer on a lenient/HA-synced load, #3494).
			// icmpTypeConstrained is nil-safe, but matchTuple below dereferences
			// app.Protocol/SourcePort/DestinationPort and would panic the
			// AppID-disabled show/session-name path on a nil entry.
			if app == nil {
```

Trace: With AppID disabled or an unstamped session, `ResolveSessionName` calls this helper. Every session formatting or application-filter comparison then scans all configured applications and reparses tuple specifications, making a session-table request O(sessions * applications).

Refutation attempt: The mapped nonzero AppID path is O(1), and enabled AppID returns `UNKNOWN`; neither guard applies to the ordinary disabled, unstamped path. No application bound, compiled fallback index, or request cache was found.

HPC/invariant check: This is control-plane work, but session-table walks should scale with sessions rather than repeatedly parse the entire application configuration.

Why it matters: Large application and session tables can make REST, CLI, and gRPC diagnostic reads consume disproportionate CPU during an incident.

Fix direction: Compile an immutable protocol/port fallback matcher when the config is accepted and reuse it across session views; add scaling benchmarks.

Labels: appid, performance, control-plane, observability

Dedup note: Searched `resolveTupleFallback|SessionMatches|tuple fallback`, `per[- ]session.*application|application.*per[- ]session`, and session-show latency terms in the corpus. Hits were #2578 precedence and #4865 nil handling, not the multiplicative fallback scan.

### C179-033: `test policy` completion lacks scalar value slots

Source IDs: A3-C002

Title: `test policy` completion lacks scalar value slots

Severity: Low

Confidence: High

Evidence: `pkg/cmdtree/tree.go:1024`
```go
					"source-ip": {Desc: "Source IP address", Children: map[string]*Node{
						"destination-ip": {Desc: "Destination IP address", Children: map[string]*Node{
							"source-port": {Desc: "Source port number", Children: map[string]*Node{
								"destination-port": {Desc: "Destination port number", Children: map[string]*Node{
									"protocol": {Desc: "IP protocol (tcp, udp)"},
								}},
							}},
							"destination-port": {Desc: "Destination port number", Children: map[string]*Node{
```

Trace: After `source-ip`, the tree descends directly to `destination-ip`; no typed placeholder consumes the supplied address. Both completion walkers consequently reject the address and cannot offer subsequent selectors.

Refutation attempt: Other operational nodes use typed or placeholder children to consume values, but none is attached to these four selectors. The zone providers do not repair scalar consumption.

HPC/invariant check: This is CLI grammar only and outside packet processing.

Why it matters: Completion and help fail in the supported policy diagnostic exactly when the tuple is being entered.

Fix direction: Add typed IP and port value nodes before each successor selector and test both completion APIs.

Labels: cli, completion, grammar

Dedup note: Searched `test policy.*completion|source-ip.*destination-ip.*completion|value slot`. #3628 concerns stale usage text, not missing value nodes.

### C179-034: Completion resolves child keywords before mandatory dynamic values

Source IDs: A3-C003

Title: Completion resolves child keywords before mandatory dynamic values

Severity: Low

Confidence: High

Evidence: `pkg/cmdtree/tree.go:1233`
```go
		name, node, matches, ok := resolveTreeWord(current, w)
		if !ok {
			if parentTyped {
				// Typed-leaf value slot consumed this word; stay at same level.
				parentTyped = false
				dynamicConsumed = true
				continue
			}
			if currentNode != nil && currentNode.HasDynamic() {
```

Trace: At `from-zone`, `to-zone` is already a child keyword. A configured zone named `to` or `to-zone` resolves as that child before the pending dynamic source-zone value is consumed, so contextual policy completion uses the wrong zone.

Refutation attempt: Keyword canonicalization after resolution does not distinguish a pending value from a keyword. Zone and classifier names are not constrained away from child keywords.

HPC/invariant check: This is parser state for completion, not a dataplane concern.

Why it matters: Legal identifier spelling can suppress completion across local CLI, remote CLI, and gRPC.

Fix direction: Track mandatory dynamic-value state explicitly and consume it before static child resolution; add exact and prefix collision tests.

Labels: cli, completion, parser-state

Dedup note: Searched `dynamic value.*keyword|keyword.*dynamic value|completion.*keyword collision|from-zone.*to-zone`. #5196 is post-resolution keyword canonicalization, not this earlier classification error.

### C179-035: A MaxInt singleton member-range wraps its induction variable

Source IDs: A3-C004

Title: A MaxInt singleton member-range wraps its induction variable

Severity: High

Confidence: High

Evidence: `pkg/config/compiler_interface_range.go:273`
```go
if en-sn >= interfaceRangeMaxMembers {
	return nil, []string{fmt.Sprintf(
		"interfaces interface-range %s: member-range %s to %s exceeds %d interfaces; ignored",
		rangeName, start, end, interfaceRangeMaxMembers)}
}
out := make([]string, 0, en-sn+1)
for i := sn; i <= en; i++ {
	out = append(out, fmt.Sprintf("%s%d", sp, i))
}
```

Trace: `MaxInt..MaxInt` passes the zero-span guard and appends once. The post-body increment wraps to `MinInt`, which remains `<= MaxInt`, so compilation grows the output until OOM.

Refutation attempt: #4807 protects `en-sn+1` capacity overflow for large spans, but it does not protect the loop increment for a singleton at the integer boundary. `strconv.Atoi` accepts `MaxInt` on the deployed 64-bit target.

HPC/invariant check: A cold compile path still requires the documented maximum 4096 expansion bound.

Why it matters: A committed or synchronized config can indefinitely pin compilation and exhaust memory.

Fix direction: Iterate by a prevalidated count or stop after appending `en`; add strict and lenient MaxInt singleton regressions.

Labels: config-compiler, integer-overflow, availability

Dedup note: Searched `expandMemberRange|member-range.*(MaxInt|overflow|wrap)`. #4807 is the distinct `en-sn+1` capacity-overflow fix.

### C179-036: Literal DDNS URL userinfo bypasses the plaintext credential gate

Source IDs: A3-C005

Title: Literal DDNS URL userinfo bypasses the plaintext credential gate

Severity: High

Confidence: High

Evidence: `pkg/config/compiler_ddns_tls.go:12`
```go
func ddnsBackendCarriesCredentials(p *DDNSProvider) bool {
	switch p.Backend {
	case "dyndns2":
		return p.Username != "" || p.Password.Reveal() != ""
	case "duckdns", "cloudflare":
		return p.APIToken.Reveal() != ""
	case "route53":
		return p.AWSAccessKeyID != "" || p.AWSSecretAccessKey.Reveal() != ""
	case "generic":
```

Trace: A generic `http://user:secret@host/...` template has no typed username/password and no `%u` or `%p`; the predicate returns false. The generic backend accepts userinfo and sends the resulting HTTP request with those credentials.

Refutation attempt: The gate covers typed generic credentials, placeholders, and HTTPS-to-HTTP redirects. It does not inspect literal userinfo, while the template validator explicitly supports it.

HPC/invariant check: This is an acceptance-time security classification, with no packet-path impact.

Why it matters: A valid strict commit can place DDNS credentials on a plaintext request.

Fix direction: Include nonempty template authority userinfo in credential classification and add HTTP/HTTPS literal-userinfo commit tests.

Labels: ddns, tls, credential-disclosure, fail-closed

Dedup note: Searched `ddns.*userinfo.*(http|tls)|userinfo.*ddns|credential.*url-template`. #4861 covers typed credential and redirect enforcement, not literal userinfo classification.

### C179-037: Malformed source-NAT pool ranges become the default PAT range

Source IDs: A3-C007

Title: Malformed source-NAT pool ranges become the default PAT range

Severity: Medium

Confidence: High

Evidence: `pkg/config/compiler_nat.go:1267`
```go
lo, err := strconv.Atoi(toks[0])
if err != nil {
	return 0, 0, false
}
hi := lo
if len(toks) >= 3 && toks[1] == "to" {
	v, err2 := strconv.Atoi(toks[2])
	if err2 != nil {
		return 0, 0, false
```

Trace: `5000 to nope` returns zero values with no retained error. Pool finalization treats zero as absent and installs `1024..65535`, after which numeric strict validation sees only a valid default range.

Refutation attempt: Numeric reversed and out-of-range values survive to the strict gate, but nonnumeric input takes the error-erasing branch. The free-form range grammar has no prior type check.

HPC/invariant check: This is cold compiler validation; malformed input must not alias an omission sentinel.

Why it matters: An intended constrained source range silently broadens to default PAT behavior.

Fix direction: Return presence plus parse error, distinguish absent from invalid state, and add malformed low/high/trailing-token tests.

Labels: nat, source-nat, silent-default, fail-open

Dedup note: Searched `source nat pool.*(nonnumeric|garbage|port range|default)|parseSourcePoolPortRange`. #3906 covers valid shape and numeric bounds, not malformed-state erasure.

### C179-038: Malformed static-NAT mapped ports collapse to whole-address NAT

Source IDs: A3-C008

Title: Malformed static-NAT mapped ports collapse to whole-address NAT

Severity: Medium

Confidence: High

Evidence: `pkg/config/compiler_nat.go:2269`
```go
func staticNATMappedPortFromKeys(keys []string) int {
	for i := 0; i+1 < len(keys); i++ {
		if keys[i] == "mapped-port" {
			if p, err := strconv.Atoi(keys[i+1]); err == nil {
				return p
			}
			return 0
		}
	}
```

Trace: `mapped-port nope` returns the same zero used for an absent mapped port. Without a destination-port match, paired-port validation is not entered and the rule compiles as ordinary whole-address static NAT.

Refutation attempt: Numeric range errors are retained and rejected, and paired half-config checks work when a match port exists. Neither distinguishes a malformed no-match modifier from absence.

HPC/invariant check: This is compiler-only; action modifiers must not collapse to the legacy action sentinel.

Why it matters: An invalid port-forward can install a broader address-wide translation.

Fix direction: Return port, presence, and parse error; reject malformed or missing values in strict compile and quarantine them on lenient load.

Labels: static-nat, grammar, fail-open

Dedup note: Searched `static nat.*(mapped-port|nonnumeric|garbage)|staticNATMappedPortFromKeys`. #2491 and #2769 cover supported port forwarding and paired-port validation, not this sentinel collision.

### C179-039: BGP neighbor policy overrides can alias inherited slice storage

Source IDs: A3-C009

Title: BGP neighbor policy overrides can alias inherited slice storage

Severity: High

Confidence: High

Evidence: `pkg/config/compiler_protocols.go:464`
```go
neighbor := &BGPNeighbor{
	Address:          nAddr,
	PeerAS:           peerAS,
	LocalAS:          groupLocalAS,
	LocalAddress:     groupLocalAddress,
	HoldTime:         groupHoldTime,
	Passive:          groupPassive,
	Description:      groupDesc,
	MultihopTTL:      groupMultihop,
	Export:           groupExport,
```

Trace: Every neighbor receives the group slice header. A per-neighbor `append` can reuse spare capacity; a later neighbor then writes the shared backing position and changes the earlier neighbor's last effective import or export policy.

Refutation attempt: Reallocation is not guaranteed. Repeated valid group exports create spare capacity, and the renderer selects the final effective policy from the already-mutated slice.

HPC/invariant check: Clone ownership during config compile; no forwarding work is required.

Why it matters: Neighbor ordering and capacity can redirect import/export route-map policy, potentially leaking or accepting routes.

Fix direction: Clone inherited `Export` and `Import` before applying neighbor overrides; test two overridden neighbors with multiple group policies.

Labels: bgp, routing, memory-aliasing, fail-open

Dedup note: Searched `BGP.*(export|import).*slice|neighbor.*(alias|backing|overwrite)|route-map.*neighbor`. #2702 is bracket-list truncation, not cross-neighbor slice mutation.

### C179-040: Static-route reject is accepted then erased

Source IDs: A3-C010

Title: Static-route reject is accepted then erased

Severity: High

Confidence: High

Evidence: `pkg/config/compiler_routing.go:145`
```go
func isRouteInlineKeyword(tok string) bool {
	switch tok {
	case "next-hop", "qualified-next-hop", "next-table", "discard", "reject", "preference", "metric", "interface":
		return true
	}
	return false
}
```

Trace: The grammar and schema accept `reject`, but the compile switches only set `Discard`; `StaticRoute` has no reject field. The FRR renderer emits nothing for a non-discard route with no next hop.

Refutation attempt: No static-route typed field, downstream renderer branch, or raw-AST consumer preserves reject. Routing-policy `reject` cases are unrelated.

HPC/invariant check: A proper reject route is static control state and needs no new per-packet work.

Why it matters: A route intended to reject can disappear, allowing less-specific or default routing instead.

Fix direction: Represent and render a real unreachable/prohibit route, or reject unsupported `reject` at commit.

Labels: routing, static-route, fail-open, silent-drop

Dedup note: Searched `static route.*reject|reject.*static route|compiler_routing.*reject|empty next-hop`. No corpus entry tracks static reject action loss.

### C179-041: Repeated SNMP community blocks can erase a clients allowlist

Source IDs: A3-C011

Title: Repeated SNMP community blocks can erase a clients allowlist

Severity: High

Confidence: High

Evidence: `pkg/config/compiler_system.go:1234`
```go
case "community":
	commName := nodeVal(child)
	if commName != "" {
		comm := &SNMPCommunity{Name: commName}
		commChildren := child.Children
		if len(child.Keys) < 2 && len(child.Children) > 0 {
			commChildren = child.Children[0].Children
		}
		for _, prop := range commChildren {
```

Trace: Hierarchical duplicate communities are siblings. A later block constructs a fresh community, validates only its own empty clients list, and overwrites the name-keyed map; `AllowsSource` treats no clients as allow-all.

Refutation attempt: Prefix validation and agent enforcement run against the replaced object. The duplicate-block validators do not cover SNMP communities.

HPC/invariant check: Merge or reject before building the immutable client-prefix cache; request-path matching remains allocation-free.

Why it matters: A valid v2c secret can become accessible outside the authored management prefixes.

Fix direction: Merge same-name blocks before validation/cache construction, or reject duplicate communities with a tolerant warning.

Labels: snmp, access-control, duplicate-block, fail-open

Dedup note: Searched `SNMP.*(community|clients).*(duplicate|overwrite|allow)|community.*clients.*allowlist`. #4834 covers malformed tokens; #5180 covers other named blocks, not community replacement.

### C179-042: Hostless RPM HTTP targets commit and are counted as path loss

Source IDs: A3-C012

Title: Hostless RPM HTTP targets commit and are counted as path loss

Severity: Medium

Confidence: High

Evidence: `pkg/config/compiler_services.go:226`
```go
if !strings.Contains(test.Target, "://") {
	continue
}
u, err := url.Parse(test.Target)
if err != nil {
	return fmt.Errorf("services rpm probe %q test %q: invalid http-get target URL %q: %w",
		probe.Name, test.Name, test.Target, err)
}
switch u.Scheme {
```

Trace: `url.Parse("http://")` succeeds with an empty host and passes the scheme switch. Runtime preserves the target until `http.NewRequestWithContext` fails; that error is not `ErrProbeSetup`, so the probe increments loss counters.

Refutation attempt: Empty-target checks do not cover a nonempty hostless URL, and neither compiler nor runtime checks `Hostname()` before request creation.

HPC/invariant check: Authority validation is constant-time setup work.

Why it matters: Invalid configuration can drive monitoring transitions as if the network path failed.

Fix direction: Require a valid nonempty host for explicit HTTP(S) targets and classify remaining construction errors as setup failures.

Labels: rpm, validation, false-path-loss

Dedup note: Searched `rpm.*(hostless|empty host|missing host)|http-get.*target.*loss|url.Parse.*rpm`. #2495 is scheme validation and #4912 is keep-alive handling, not missing authority.

### C179-043: Parser error accumulation amplifies a bounded input into unbounded diagnostics

Source IDs: A3-C013

Title: Parser error accumulation amplifies a bounded input into unbounded diagnostics

Severity: Medium

Confidence: High

Evidence: `pkg/config/parser.go:184`
```go
	var nodes []*Node
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenEOF || tok.Type == TokenRBrace {
			break
		}
		if tok.Type == TokenError {
			p.addError(tok.Line, tok.Column, tok.Value)
			p.lexer.Next() // consume error token
			continue
```

Trace: Each unexpected input byte produces a formatted `TokenError` and one retained `ParseError`. A payload below the 16 MiB ingress ceiling can therefore create roughly one error object per byte before any caller reads only the first error.

Refutation attempt: The size and nesting-depth limits bound input and recursion, respectively, but neither caps the error slice or formatted messages on this flat invalid-token path.

HPC/invariant check: Parser memory and CPU must remain bounded per accepted config payload; this is outside the data path.

Why it matters: A malformed configuration or sync payload can cause large allocations, GC pressure, and blocked configuration work.

Fix direction: Cap parser errors, append one terminal sentinel, then drain or stop tokenization without retaining more diagnostics.

Labels: parser, availability, control-plane, memory

Dedup note: Searched `parse error.*(cap|limit|memory)|too many parse errors|unexpected character.*(OOM|memory)`. No parser diagnostic-amplification issue was found.

### C179-044: Lexer silently discards unmatched bracket syntax

Source IDs: A3-C014

Title: Lexer silently discards unmatched bracket syntax

Severity: Medium

Confidence: High

Evidence: `pkg/config/lexer.go:120`
```go
			if c == '[' {
				if tok, ok := l.tryBracketedEndpointLiteral(); ok {
					return tok
				}
			}
			l.advance()
			continue
		}
```

Trace: Apart from a narrow IPv6 endpoint literal, every bracket is erased before parsing. A brackets-only payload reaches EOF with no tokens or error and can be accepted as an empty candidate.

Refutation attempt: The recursion guard deliberately treats brackets as stripped list sugar; no balance or placement state exists. String, comment, and brace errors do not observe erased brackets.

HPC/invariant check: Delimiter validation is cold parser work.

Why it matters: Malformed override or sync syntax can produce a different accepted tree with no diagnostic.

Fix direction: Tokenize list brackets or maintain balanced list state, retaining the bracketed IPv6 endpoint exception.

Labels: parser, configuration-integrity, fail-closed

Dedup note: Searched `unmatched bracket|unterminated bracket|bracket.*empty config|bracket.*strip`. #2419 is valid list-value collapse, not global delimiter erasure.

### C179-045: Lenient mixed-case host-inbound tokens lose Junos-host exemptions

Source IDs: A3-C015

Title: Lenient mixed-case host-inbound tokens lose Junos-host exemptions

Severity: Medium

Confidence: High

Evidence: `pkg/config/junos_host_deny.go:827`
```go
func zoneCoarseAdmitsIKE(zc *ZoneConfig) bool {
	if zc == nil {
		return false
	}
	svc := zoneEffectiveSystemServices(zc)
	for _, s := range svc {
		if s == "ike" || s == "ipsec" || HostInboundFullAdmitService(s) {
			return true
		}
```

Trace: Lenient compilation retains a warning-only raw `IKE` token. The nft and Rust host-inbound paths lowercase it, but this projection compares raw strings and omits the IKE/IPsec shield before an otherwise representable Junos-host deny.

Refutation attempt: Strict commits reject wrong case, but load and peer-sync intentionally downgrade it to a warning. `zoneEffectiveSystemServices` copies raw strings without normalization.

HPC/invariant check: Normalize during projection so the kernel fine policy remains consistent with coarse host-inbound behavior.

Why it matters: A tolerated persisted configuration can lose direct-host IKE or alter ident-reset behavior after restart or HA sync.

Fix direction: Normalize effective host-inbound tokens in the exemption SSOT and add mixed-case lenient projection and daemon tests.

Labels: host-inbound, HA, ipsec, configuration-compatibility

Dedup note: Searched `wrong case.*(ike|ident|host-inbound)|CoarseAdmitsIKE|zoneCoarseAdmitsIKE`. #3200 validates tokens and #4146 adds projection; neither covers their lenient raw-case interaction.

### C179-046: Security log stream schema rejects supported severities

Source IDs: A3-C016

Title: Security log stream schema rejects supported severities

Severity: Low

Confidence: High

Evidence: `pkg/config/schema_security.go:29`
```go
var (
	syslogLogModes   = []string{"event", "stream"}
	syslogLogFormats = []string{"binary", "sd-syslog", "structured", "syslog"}
	syslogSeverities = []string{"error", "info", "warning"}
	syslogFacilities = []string{
		"auth", "change-log", "daemon", "kern",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
```

Trace: Security stream `severity critical`, `notice`, `debug`, and the other system-supported values fail `ValidateEnum(syslogSeverities)`. The runtime calls `logging.ParseSeverity`, which supports the complete ten-value vocabulary.

Refutation attempt: No stream-specific renderer or runtime limitation narrows the values. The adjacent `junosSyslogSeverities` explicitly records the full accepted contract.

HPC/invariant check: This is schema parity only.

Why it matters: Valid logging threshold configurations cannot be committed or migrated on the security stream surface.

Fix direction: Share the complete severity SSOT between system syslog and security streams and test all values in both grammar shapes.

Labels: logging, schema, configuration, vsrx-parity

Dedup note: Searched `security log.*severity|log stream.*severity|syslogSeverities|ParseSeverity.*security`. Existing stream issues concern fields, TLS, and reconnects, not severity vocabulary.

### C179-047: Unknown shared-UMEM modes silently disable the feature

Source IDs: A3-C017

Title: Unknown shared-UMEM modes silently disable the feature

Severity: Low

Confidence: High

Evidence: `userspace-dp/src/afxdp/shared_umem.rs:283`
```rust
fn parse_shared_umem_mode(value: &str) -> SharedUmemMode {
    match value {
        "auto" | "on" | "enable" | "enabled" => SharedUmemMode::CrossNic,
        "same-device-debug" | "same_device_debug" => SharedUmemMode::SameDeviceDebug,
        "cross-nic" | "cross_nic" => SharedUmemMode::CrossNic,
        "off" | "disable" | "disabled" => SharedUmemMode::Off,
        _ => SharedUmemMode::Off,
    }
}
```

Trace: The config schema leaves `shared-umem mode` untyped and the Go compiler preserves its string. A typo such as `cross-nci` reaches this wildcard arm and selects `Off`.

Refutation attempt: Adjacent dataplane controls are enum-validated; no strict shared-UMEM semantic gate was found. Runtime aliases do not justify arbitrary unrecognized input.

HPC/invariant check: The fallback remains memory-safe but violates the explicit performance/ownership request.

Why it matters: A deployment typo can silently lose requested cross-NIC shared-UMEM behavior and capacity.

Fix direction: Validate canonical mode values at commit and make unknown runtime decoding observable or erroneous.

Labels: shared-umem, AF_XDP, schema, silent-default

Dedup note: Searched `shared umem.*(unknown|typo|mode|silent|off)|parse_shared_umem_mode`. Corpus matches concern unrelated shared-UMEM lifecycle and telemetry issues.

### C179-048: Hierarchical leaves can omit a semicolon before a closing brace

Source IDs: A3-C018

Title: Hierarchical leaves can omit a semicolon before a closing brace

Severity: Low

Confidence: High

Evidence: `pkg/config/parser.go:346`
```go
default:
	// No semicolon or brace -- treat as implicit leaf
	// (some Junos statements can omit trailing semicolon at EOF)
	return &Node{
		Keys:     keys,
		IsLeaf:   true,
		Inactive: inactive,
		Line:     line,
		Column:   col,
	}
```

Trace: For `system { host-name fw }`, key parsing stops at `}` and falls through the default implicit-leaf branch. The parent then consumes `}`, so the missing terminator is erased.

Refutation attempt: EOF may intentionally permit an implicit leaf, but the code does not restrict that exception to EOF. Later schema stages cannot recover the missing token.

HPC/invariant check: This is grammar validation only.

Why it matters: Truncated or hand-edited hierarchical configuration can commit as a silently normalized tree.

Fix direction: Allow implicit leaves only at EOF; report a missing semicolon before `}` and retain recovery behavior if desired.

Labels: parser, grammar, configuration-integrity

Dedup note: Searched `missing semicolon|semicolon.*rbrace|implicit leaf|unterminated statement`. No equivalent parser issue was found.

### C179-049: Equal SNMP client prefixes can bypass restrict by insertion order

Source IDs: A3-C019

Title: Equal SNMP client prefixes can bypass restrict by insertion order

Severity: Medium

Confidence: High

Evidence: `pkg/config/snmp_clients.go:92`
```go
bestBits := -1
bestAllow := false
for _, cn := range nets {
	if !cn.net.Contains(srcIP) {
		continue
	}
	if cn.ones > bestBits {
		bestBits = cn.ones
		bestAllow = !cn.restrict
	}
```

Trace: `10.0.0.1/24` and `10.0.0.2/24 restrict` canonicalize to the same network. The first allow records 24 bits; the later equal-length deny cannot replace it because the comparison is strict `>`.

Refutation attempt: Prefix syntax validation succeeds for both entries and no canonical duplicate/action-conflict validation runs. The real UDP serving path supplies a nonnil source IP.

HPC/invariant check: Normalize or reject at compile time; the current allocation-free request matcher can remain unchanged.

Why it matters: The configured SNMP source boundary can be bypassed by an equivalent earlier allow spelling.

Fix direction: Canonicalize prefixes and reject conflicting equal actions; use deny-wins for equal-length ties as defense in depth.

Labels: snmp, access-control, fail-open

Dedup note: Searched `SNMP.*(equal|same|canonical|duplicate).*(prefix|restrict)|restrict.*client`. #4834 is malformed-token handling, not canonical equal-prefix conflict.

### C179-051: Screen status inventory omits alarm-without-drop mode

Source IDs: A3-C021

Title: Screen status inventory omits alarm-without-drop mode

Severity: Low

Confidence: High

Evidence: `pkg/config/screen_inventory.go:188`
```go
func ScreenEnabledCheckList(p *ScreenProfile) []string {
	checks := ScreenChecks(p)
	if len(checks) == 0 {
		return nil
	}
	thresholds := ScreenThresholds(p)
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		// SYN-flood keys its numeric value under the attack-threshold key
		// rather than the bare "syn-flood" presence token.
```

Trace: `AlarmWithoutDrop` changes screen forwarding from drop to alarm-and-permit, yet the shared inventory reads only checks and thresholds. REST, gRPC, and text renderers consume that inventory or equivalent fields and expose no mode bit.

Refutation attempt: The authored config can reveal the leaf, so this is an operational-observability gap rather than an enforcement failure. No inventory response or alternate status field exposes effective audit mode.

HPC/invariant check: Adding one configuration-state field does not affect packet processing.

Why it matters: Operators and automation can mistake audit-only screen protection for drop enforcement.

Fix direction: Include an explicit `alarm_without_drop` field in structured responses and render it in shared text inventory helpers.

Labels: screen, observability, API, CLI

Dedup note: Searched `AlarmWithoutDrop|alarm-without-drop|screen.*(inventory|show|API|CLI).*(audit|log-only|drop)`. #4176 implements the mode; no result records its operational inventory omission.

### C179-052: Confirm resolution deletes durable recovery intent after a failed replacement write

Source IDs: A4-C001

Title: Confirm resolution deletes durable recovery intent after a failed replacement write

Severity: High

Confidence: High

Evidence: [`pkg/configstore/store_commit.go:631`](/home/ps/git/codex-bpfrx/pkg/configstore/store_commit.go:631) removes `confirm.json` regardless of the `perr` branch immediately above.

```go
	// #4577: the confirm window is resolved (rolled back) — drop the persisted
	// crash-recovery state so a restart does not re-arm/re-roll a completed
	// window. Idempotent: a crash between the writeActive above and this
	// remove leaves a confirm.json whose deadline has passed and whose
	// rollback target equals the now-persisted active, so a Load recovery
	// re-runs the rollback as a no-op.
	s.removeConfirmState()
```

Trace: A confirmed commit durably records active C and rollback target A in `confirm.json`. On timeout, `PromoteRollback` changes memory to A; a failed `writeActive(A)` starts the delayed retry at `store_commit.go:626-629`, then the shown call durably deletes the record. A crash before the retry succeeds leaves C as active with no pending-confirm record. `recoverPendingConfirmLocked` repeats this ordering at `store_persist.go:177-185`; `SyncApply` also calls `clearPendingConfirmLocked` before its degrade-not-fail active write at `store.go:570-590`.

Refutation attempt: I checked `DeleteConfirm`, `noteActivePersistFailureLocked`, the retry loop, boot recovery, and `SyncApply`. Directory fsync makes the deletion survive, while the retry intentionally has no first-attempt barrier or shutdown join. No transaction state, write-ahead record, or successful-write condition keeps a recovery target alive across the crash window.

HPC/invariant check: No packet-path cost is involved. The persistence invariant is that a pending-confirm recovery record cannot be removed until the rollback or authoritative replacement is durable.

Why it matters: A policy guarded by `commit confirmed` can become permanent after the disk failure and reboot sequence that the recovery record exists to handle; a secondary can likewise boot stale policy after a failed authoritative sync write.

Fix direction: Model resolution as a durable transition: write the rollback or sync target first, then delete/replace `confirm.json` only on success. Preserve enough intent on Option-B failure for boot recovery to finish the replacement. Inject active-write failures for timeout, boot recovery, and SyncApply, then create a fresh Store before the retry runs.

Labels: configstore, durability, commit-confirmed, ha, fail-open

Dedup note: I searched `dedup-index.txt` for `confirm`, `rollback`, `confirm.json`, `persist`, and `commit confirmed`. The corpus has the earlier failure-to-create-record and non-durable-delete findings (`codex-review-175.md` and tracked `#4864`), but not deletion of an otherwise valid record after its replacement write failed. The root cause and fix locus are the resolution ordering, not record creation or unlink durability.

### C179-053: The boot-critical committed marker is noncanonical and outside AES-GCM authentication

Source IDs: A4-C002

Title: The boot-critical committed marker is noncanonical and outside AES-GCM authentication

Severity: Medium

Confidence: High

Evidence: [`pkg/configstore/crypto.go:204`](/home/ps/git/codex-bpfrx/pkg/configstore/crypto.go:204) seals only the JSON body and supplies `nil` additional authenticated data. The outer header parser at `pkg/configstore/envelope.go:303-308` then maps every nonzero integer to committed.

```go
	env := encryptedTreeEnvelope{
		Format: encryptedTreeFormat,
		PRF:    prf,
		Salt:   base64.StdEncoding.EncodeToString(salt),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		Data:   base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, data, nil)),
	}
	return marshalEnvelope(env)
```

Trace: `writeTreeMarked` encrypts the body before `wrapEnvelope` prepends `committed=<n>`. A `committed=0` never-committed marker can therefore be changed to `1`, `2`, or `-1` without an encrypted-body tag failure; the parser uses `n != 0`. `readTreeMeta` propagates that boolean into `Store.Load`, and `classifyBoot` treats `everCommitted=true` as normal ownership rather than bootstrap.

Refutation attempt: I checked envelope version/min-reader gates, header parsing, `writeTreeMarked`, `Seal`/`Open`, marker propagation, and daemon boot classification. File mode restricts ordinary users, but it neither detects storage corruption nor cryptographically binds interpretation-changing metadata. The first-rollback empty body may be plaintext, which strengthens rather than refutes the missing integrity boundary; encrypted trees additionally authenticate no header AAD.

HPC/invariant check: No dataplane impact. Safety-class metadata must have a canonical encoding and be integrity-bound to the body whose boot interpretation it changes.

Why it matters: A one-token offline corruption or privileged storage edit can turn a protected never-committed empty state into normal boot without the encryption key, permitting interface ownership with no committed policy.

Fix direction: Accept exactly `0` and `1`, reject duplicates/noncanonical forms, and version a format that authenticates a canonical header as GCM AAD or moves the marker inside the encrypted object. Add marker-bit-flip tests for encrypted and plaintext/migration cases.

Labels: configstore, cryptography, integrity, bootstrap, fail-open

Dedup note: I searched `dedup-index.txt` for `committed`, `marker`, `envelope`, `auth`, `AES`, and `tamper`. The corpus records the `#1922` marker introduction and an unrelated malformed-nonce panic, but no canonical parsing or authenticated binding for this outer boot decision. The root cause is header integrity, not ciphertext nonce validation.

### C179-054: JSON null active bodies decode as valid empty configuration

Source IDs: A4-C003

Title: JSON null active bodies decode as valid empty configuration

Severity: High

Confidence: High

Evidence: [`pkg/configstore/db.go:293`](/home/ps/git/codex-bpfrx/pkg/configstore/db.go:293) unmarshals into a preallocated tree with no top-level-kind validation.

```go
	tree := &config.ConfigTree{}
	if err := json.Unmarshal(data, tree); err != nil {
		return nil, true, fmt.Errorf("parse %s: %w", path, err)
	}

	// Unexpected-plaintext warning (#4579 A4-06). When master-password is
	// set, every write path encrypts the body (maybeEncryptTreeJSON keyed
	// off the tree's master-password leaf), so a config that DECLARES a
	// master-password should never be read back as plaintext. If it is,
```

Trace: A legacy/plaintext active DB, or an enveloped but unencrypted body, containing `null` is accepted by `unmarshalEnvelope` as a body with no envelope fields. Go unmarshals `null` into the existing `*ConfigTree` without error and leaves its zero value. `readTreeMeta` returns a non-nil tree with the legacy/current default committed state; `Store.Load` compiles it and normal boot proceeds instead of returning `ErrConfigDBUnreadable`.

Refutation attempt: I checked the unknown-encrypted-format rejection, `stripEnvelope`, `readTreeMeta`, `Store.Load`, and boot classification. AES-GCM protects an encrypted `null` replacement, so the reachable cases are legacy/plaintext or intentionally non-encrypted current bodies. That limitation does not restore the fail-closed decode contract: syntax errors fail, but a semantically impossible scalar body silently becomes a zero policy.

HPC/invariant check: No packet-path impact. Authoritative persisted state must reject malformed/partial top-level JSON rather than relying on zero-value decode behavior.

Why it matters: Corruption, a bad restore, or a partial external transformation can boot a firewall with policy absent rather than leave an observable recovery error.

Fix direction: Inspect a `json.RawMessage` or token stream first and require an object before decoding `ConfigTree`; explicitly reject `null`, arrays, and scalars while documenting the valid empty-object representation. Cover plaintext and encrypted-envelope framing separately.

Labels: configstore, persistence, json, fail-open, policy

Dedup note: I searched `dedup-index.txt` for `null`, `empty-load`, `config DB`, `JSON`, and `encrypted-envelope`. The tracked `#4888` issue rejected unknown encrypted envelope fields that formerly fell through to an empty tree. This is distinct: `null` has no discriminator fields, is syntactically valid, and passes the intentionally retained legacy/plaintext path.

### C179-055: Zeroize omits external secret archives and atomic-write crash remnants

Source IDs: A4-C004

Title: Zeroize omits external secret archives and atomic-write crash remnants

Severity: High

Confidence: High

Evidence: [`pkg/configstore/factory_reset.go:85`](/home/ps/git/codex-bpfrx/pkg/configstore/factory_reset.go:85) limits the post-DB sweep to names in `configDir`.

```go
	entries, err := os.ReadDir(configDir)
	fail(err)
	for _, f := range entries {
		name := f.Name()
		if strings.HasSuffix(name, ".conf") ||
			strings.HasPrefix(name, "rollback") ||
			name == ".config.journal" ||
			strings.HasPrefix(name, ".config.journal.") ||
			isTextRollbackSlot(name, configBase) {
			fail(os.Remove(filepath.Join(configDir, name)))
```

Trace: `writeArchive` writes full cleartext formatted configurations to its separate directory, and daemon configuration defaults that directory to `/var/lib/xpf/archive` when archival is enabled (`daemon_apply.go:1711-1721`). `FactoryResetConfigDir` has neither that directory nor an artifact registry. Separately, `fsatomic` documents crash-leaked `.<base>.tmp-*` files; the shown matcher admits neither their hidden prefix nor their suffix, and the DB startup sweep only covers `.configdb`.

Refutation attempt: I inspected the full reset primitive, CLI caller, daemon archive configuration, archive writer, `fsatomic` naming contract, and existing zeroize tests. Key-first DB erasure and parent fsync are correct, and 0600/0700 protects live data, but neither removes external archives or top-level temp remnants. No caller supplies archive roots or verifies those secret-bearing locations are empty.

HPC/invariant check: No packet-path impact. A successful zeroize must remove every xpf-owned recoverable configuration replica before announcing erasure.

Why it matters: A decommissioned or reassigned appliance can retain full prior-tenant credentials and policy after reporting that configuration was erased.

Fix direction: Maintain one writer/zeroizer artifact inventory that includes configured/default archive roots and provenance-safe fsatomic-temp patterns. Quiesce writers, erase or cryptographically destroy external archives, fsync affected parents, and verify owned roots before success.

Labels: configstore, zeroize, secrets, durability, data-remanence

Dedup note: I searched `dedup-index.txt` for `zeroize`, `factory reset`, `archive`, `temp`, and `remanence`. Prior findings cover the former DB/journal/local-rollback omission, TLS and rendered-config remnants, and plaintext archive protection. None cover reset's omission of writer-owned external archives and crash temps; this is an erasure-inventory failure, not at-rest encryption or the already-fixed DB wipe.

### C179-056: Shifted rollback tombstones revive stale valid slots after restart

Source IDs: A4-C005

Title: Shifted rollback tombstones revive stale valid slots after restart

Severity: Medium

Confidence: High

Evidence: [`pkg/configstore/store_commit.go:854`](/home/ps/git/codex-bpfrx/pkg/configstore/store_commit.go:854) skips a tombstone at its new in-memory position without writing a durable marker.

```go
	if entry.Config == nil {
		// #4810: a tombstoned slot (unreadable/corrupt at load, see
		// loadRollbackHistory) has no config text to persist. Leave
		// its on-disk file untouched — writing would dereference a
		// nil Config, and removing it would let a NEXT boot's
		// os.IsNotExist break() truncate every slot after it. The
		// slot stays visibly broken (same tombstone next boot) until
		// an operator fixes it out-of-band, instead of silently
```

Trace: A load error makes logical slot 2 a nil entry. A subsequent commit pushes it to logical slot 3, where this branch preserves the valid residual bytes already in file 3. The existing `TestSaveRollbackFilesSkipsTombstoneWithoutPanic` deliberately asserts those bytes stay identical. On the next Store construction, `loadRollbackHistory` parses file 3 successfully, the tombstone disappears, and `rollback 3` selects stale content rather than failing unavailable.

Refutation attempt: I checked history ordering, both tombstone creation paths, `rollbackEntry`, load/save cleanup, and the existing regression. The in-memory position is protected before restart, but the residual file cannot encode which generation it represents after the ring shifts. Avoiding a panic or a hole does not preserve identity across reload.

HPC/invariant check: No packet-path impact. Every durable rollback index must refer to the same generation or an explicit unavailable marker across a commit and restart.

Why it matters: A numbered rollback that correctly rejected a damaged generation can later restore a different obsolete configuration, including stale policy or credentials.

Fix direction: Persist a versioned tombstone/manifest with stable generation identity, atomically rewrite the index mapping, and extend the current regression through a fresh Store load.

Labels: configstore, rollback, durability, state-identity

Dedup note: I searched `dedup-index.txt` for `tombstone`, `rollback`, `shift`, `stale`, and `slot`. Tracked `#4810` fixed load-time bare skipping that immediately shifted later slots. This successor bug occurs only after a later save and restart because the new tombstone position is never represented on disk.

### C179-057: Retired-dataplane migration misses wildcard groups that expand into system

Source IDs: A4-C006

Title: Retired-dataplane migration misses wildcard groups that expand into system

Severity: Medium

Confidence: High

Evidence: [`pkg/configstore/dataplane_retire.go:121`](/home/ps/git/codex-bpfrx/pkg/configstore/dataplane_retire.go:121) only sends direct literal `system` children to the rewrite helper.

```go
	for _, groupsRoot := range groupsBlocksOf(tree) {
		for _, group := range groupsRoot.Children {
			if group == nil {
				continue
			}
			// A group may contain multiple `system { ... }` stanzas
			// the same way a top-level config can.
			for _, groupSystem := range systemBlocksOfNode(group) {
				rewrites += rewriteRetiredLeavesIn(groupSystem, caller)
			}
```

Trace: A persisted or peer-synced group can contain `<*> { dataplane-type ebpf; }` and be applied to a top-level `system`. The existing wildcard master-password test proves that expansion merges this form into `system`, but `systemBlocksOfNode` does not recurse through `<*>`. Load and SyncApply invoke this rewrite before compile; post-expansion `validateDataplaneTypeStrict` then rejects the unrevised retired value.

Refutation attempt: I inspected the two rewrite passes, `systemBlocksOfNode`, wildcard merge semantics, the existing wildcard group regression, and strict validation order. Literal nested `system` forms are covered, but wildcard reachability is real and no lenient compiler option downgrades the retired-dataplane gate.

HPC/invariant check: No packet path is reached. Every persisted/synced spelling that expands to a retired backend must be normalized before the unconditional strict compiler gate.

Why it matters: A valid pre-retirement configuration can fail boot or put HA config sync into a repeat-failure loop solely because it used wildcard group syntax.

Fix direction: Normalize retired values after group expansion under explicit Load/Sync semantics, or implement a group-semantic traversal that covers wildcard destinations without rewriting unrelated leaves. Test hierarchical Load and SyncApply for both retired values.

Labels: configstore, migration, apply-groups, availability, ha

Dedup note: I searched `dedup-index.txt` for `dataplane-type`, `retired`, `group`, and `wildcard`. The corpus records retirement and literal-group rewriting, while the master-password wildcard item demonstrates the syntax's reachability. It does not cover this rewrite/strict-validation gap, whose root cause is wildcard expansion in the migration path.

### C179-058: Disk loading bypasses configuration byte bounds and retains fifty rollback trees

Source IDs: A4-C007

Title: Disk loading bypasses configuration byte bounds and retains fifty rollback trees

Severity: Medium

Confidence: High

Evidence: [`pkg/configstore/store_commit.go:935`](/home/ps/git/codex-bpfrx/pkg/configstore/store_commit.go:935) reads every rollback file in full before parsing.

```go
	var entries []*HistoryEntry
	for i := 1; i <= s.history.MaxSize(); i++ {
		path := s.rollbackPath(i)
		data, err := os.ReadFile(path)
		if err != nil {
			// #3441 L2: stop only at a genuinely missing slot (the
			// contiguous-sequence terminator). A transient/permission
			// error on an intermediate slot must NOT drop all the later
			// readable slots — log and continue so the rest of the
			// history still loads.
```

Trace: `MaxConfigSize` documents a 16 MiB ingress bound, but `readTreeMeta` and this loop use unbounded `os.ReadFile`. The constructor fixes history capacity at 50. Startup can therefore allocate a corrupt/oversized active or rollback file before parsing, then keep up to fifty parsed rollback trees; valid near-limit history can consume hundreds of MiB before AST overhead.

Refutation attempt: I inspected all `checkConfigSize` call sites, DB reads, `loadRollbackHistory`, parser handling, and `NewHistory(50)`. Transport and edit ingress are bounded, but no disk `Stat`, limited reader, per-file check, aggregate budget, or lazy history representation exists. Owner-only storage reduces hostile writers but not restores, corruption, or operator-generated near-limit histories.

HPC/invariant check: No packet-path impact. Persisted recovery state needs both per-file and aggregate byte bounds before allocation.

Why it matters: Startup can OOM-loop before recovery controls are available, even with syntactically valid history, or a single oversized restored file can exhaust memory.

Fix direction: Enforce a pre-allocation active-file ceiling, cap/tombstone oversize rollback slots with a safe diagnostic, add an aggregate rollback budget, and consider lazy history decoding. Cover boundary, fifty-large-entry, and sparse-oversize cases.

Labels: configstore, memory, availability, bounds, startup

Dedup note: I searched `dedup-index.txt` for `rollback`, `memory`, `OOM`, `size`, `16 MiB`, and `history`. Existing bounds findings are ingress-facing and do not identify unbounded active/rollback disk loading or aggregate retained-history memory. The affected contract is startup persistence, not network payload admission.

### C179-059: Auto-archive has unbounded asynchronous snapshot admission

Source IDs: A4-C008

Title: Auto-archive has unbounded asynchronous snapshot admission

Severity: Medium

Confidence: High

Evidence: [`pkg/configstore/store_commit.go:211`](/home/ps/git/codex-bpfrx/pkg/configstore/store_commit.go:211) captures a full formatted tree and starts a goroutine for every archive-enabled commit.

```go
	if s.archiveDir != "" {
		dir := s.archiveDir
		max := s.archiveMax
		if max <= 0 {
			max = 10
		}
		data := s.active.Format()
		ts := time.Now()
		seq := s.archiveSeq.Add(1)
		go func() {
```

Trace: With a slow or stalled archive filesystem, each successful commit captures `data` into a new closure. `writeArchive` can block in directory creation, atomic file I/O, enumeration, or removal; launch returns immediately and later commits keep admitting snapshots. `archiveMax` limits retained files only, not outstanding goroutines, bytes, descriptors, or rotations.

Refutation attempt: I inspected commit locking, `SetArchiveConfig`, `ArchiveConfig`, `writeArchive`, rotation, and archive tests. The Store lock serializes the capture but is released before I/O; there is no semaphore, worker, bounded queue, cancellation, shutdown ownership, or coalescing. The per-config size cap bounds one snapshot, not their count.

HPC/invariant check: No packet path is involved. Best-effort control-plane I/O requires bounded admission and lifecycle ownership when its destination can stall.

Why it matters: Repeated commits during archive-storage trouble can grow memory, goroutines, file descriptors, and concurrent rotation work until the control plane fails.

Fix direction: Use one lifecycle-managed archive worker with a bounded queue and explicit overflow/coalescing policy, cancellation/shutdown semantics, serialized rotation, and backlog/failure metrics. Test a blocked write seam with many commits.

Labels: configstore, archive, concurrency, memory, backpressure

Dedup note: I searched `dedup-index.txt` for `archive`, `goroutine`, `queue`, `backpressure`, `writeArchive`, and `unbounded`. The corpus covers archive naming, permissions, and rotation races, not admission of unbounded blocked writers holding complete snapshots. This is a concurrency/resource root cause, not retention correctness.

### C179-060: Archive retention deletes the newest commit after a backward wall-clock step

Source IDs: A4-C009

Title: Archive retention deletes the newest commit after a backward wall-clock step

Severity: Low

Confidence: High

Evidence: [`pkg/configstore/store_persist.go:506`](/home/ps/git/codex-bpfrx/pkg/configstore/store_persist.go:506) orders archives lexically and removes the first entries.

```go
	// Sort alphabetically (timestamps sort naturally)
	sort.Strings(archives)

	// Remove oldest.
	for i := 0; i < len(archives)-maxArchives; i++ {
		path := filepath.Join(dir, archives[i])
		if err := archiveRemoveErr(path); err != nil {
			slog.Warn("failed to remove old archive", "path", path, "err", err)
		}
	}
```

Trace: `writeArchive` names files `config-<wall-clock timestamp>.<process-local seq>.conf` and writes before rotating. At the retention limit, an NTP/manual backward step gives the newest commit a name lexically earlier than retained files; its suffix cannot correct the leading timestamp. The following rotation removes that new file. Restart also resets the suffix sequence, so it is not a durable ordering source.

Refutation attempt: I checked filename formation, sequence capture, write-before-rotate order, filtering, sorting, and removal. The sequence prevents same-name collisions in one process, but only breaks equal timestamp ties. No durable generation or manifest establishes commit order across wall-clock changes or restart.

HPC/invariant check: No packet-path impact. Retention stated as most-recent commits must use a monotonic commit identity, not adjustable wall-clock lexical order.

Why it matters: A routine clock correction can silently discard the archive most likely needed for immediate recovery while retaining an older configuration.

Fix direction: Add a durable monotonic archive generation/manifest and rotate by it, using wall time only as display metadata. Test backward steps, equal timestamps, process restart, and out-of-order async completion.

Labels: configstore, archive, time, retention

Dedup note: I searched `dedup-index.txt` for `archive`, `clock`, `NTP`, `timestamp`, `rotate`, and `prune`. Existing archive work fixes collision/mislabel risks and cleanup races; it does not make retention order monotonic under a backward clock. The root cause is ordering, not filename uniqueness.

### C179-061: Journal append follows a path that permission migration rejected as a symlink

Source IDs: A4-C010

Title: Journal append follows a path that permission migration rejected as a symlink

Severity: Low

Confidence: High

Evidence: [`pkg/configstore/journal/journal.go:267`](/home/ps/git/codex-bpfrx/pkg/configstore/journal/journal.go:267) opens the journal path without a no-follow or post-open regular-file check. The first-use migration instead returns at `journal.go:201-205` when it finds a symlink.

```go
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open journal: %w", err)
	}
	defer f.Close()

	// Torn-tail self-heal: a crash between a previous write and its
	// fsync can leave a partial final line. Starting this record on a
	// fresh line confines the damage to that one record (which the
	// tail reader's parse-or-skip rule already drops).
```

Trace: A restored or tampered config directory contains `.config.journal` as a symlink. First `Log` runs `migratePermsLocked`; `chmodOwnerOnly` warns and leaves it. If rotation is not due, `os.Stat` and the shown `os.OpenFile` follow the final link, then the daemon appends and fsyncs the target instead of creating the journal.

Refutation attempt: I inspected migration, append locking, rotation, open flags, and the symlink test. The migration guard only protects `chmod`; no `O_NOFOLLOW`, descriptor-relative secure open, `Lstat` rejection in `Log`, or post-open regular-file validation precedes writes. Root-owned 0700 storage limits unprivileged exploitation, which supports Low severity but does not make malformed restored state safe.

HPC/invariant check: No packet-path impact. A path rejected as an owned journal segment during migration must not later be followed for privileged append.

Why it matters: Malformed on-disk state can redirect root daemon audit writes, corrupt another file, and leave the intended audit trail absent.

Fix direction: Open with a no-follow primitive or directory-fd-relative secure open, verify the descriptor is an owner-controlled regular file, and apply the same contract to rotation segments. Extend the symlink regression through `Append`/`Log` and assert target bytes do not change.

Labels: configstore, journal, filesystem, symlink

Dedup note: I searched `dedup-index.txt` for `journal`, `symlink`, `nofollow`, and `append`. Tracked `#5188` is permission migration for old journal modes and contains the chmod-through-link guard. It does not cover the later append open following the rejected link; the root cause is inconsistent filesystem ownership enforcement across operations.

### C179-062: Heartbeat anti-replay accepts alternation back to a retired authenticated session

Source IDs: A5-C001

Title: Heartbeat anti-replay accepts alternation back to a retired authenticated session

Severity: High

Confidence: High

Evidence: `pkg/cluster/heartbeat.go:492`

```go
func (a *heartbeatAuthReplay) admit(session, counter uint64) bool {
	if !a.seen || session != a.session {
		a.session = session
		a.counter = counter
		a.seen = true
		return true
	}
	if counter > a.counter {
		a.counter = counter
		return true
```

Trace: The read loop verifies the HMAC, then calls `admit` before updating `lastSeen` and invoking `handlePeerHeartbeat` (`pkg/cluster/heartbeat.go:750-773`). Once B is accepted, a captured valid A frame changes the one stored session back to A; the next B frame changes it back again. An on-link recorder able to inject authenticated bytes can repeat this and keep stale peer state live or drive election from it.

Refutation attempt: HMAC prevents fabrication, not replay of an already-valid byte sequence. Cluster-ID and duplicate-node checks do not encode an incarnation, and the existing test covers only A-to-B, not A-to-B-to-A. The routine-restart requirement explains accepting a new session but does not justify accepting a previously retired one.

HPC/invariant check: Control path only, with O(1) state today. The invariant is that a peer incarnation cannot regress; any bounded retired-ID or epoch mechanism must retain allocation-free heartbeat admission.

Why it matters: Authentication is advertised as replay protection, yet recorded control traffic can refresh liveness and apply stale role/priority information.

Fix direction: Bind an authenticated boot epoch or retain a bounded retired-session set and reject a return to a retired ID. Test A1, B1, A2 through the real receiver and assert A2 does not refresh liveness or election state.

Labels: security, ha, heartbeat, replay

Dedup note: Searched `heartbeat.*replay|replay.*heartbeat|session.*watermark|control.*replay` and `pkg/cluster/heartbeat.go` in the duplicate corpus. No tracked heartbeat-session rollback root appeared; WireGuard/SNMP replay material is a different protocol and fix locus.

### C179-063: Missing local interface monitor retains healthy election weight

Source IDs: A5-C002

Title: Missing local interface monitor retains healthy election weight

Severity: High

Confidence: High

Evidence: `pkg/cluster/monitor.go:292`

```go
		link, err := nlh.LinkByName(linuxName)
		if err != nil {
			// Check if interface belongs to peer based on FPC slot.
			slot := config.InterfaceSlot(im.Interface)
			if slot >= 0 && config.SlotToNodeID(slot) != mon.mgr.NodeID() {
				continue // peer's interface
			}
			slog.Warn("cluster monitor: local interface missing",
				"rg", rg.ID, "interface", im.Interface)
			continue
```

Trace: A local monitor that was previously up has no failure entry. On netdev removal, rename, or unresolved startup name, this branch returns before `evaluateTransition` and `SetMonitorWeight`; the previous healthy contribution remains and an already-primary node is not demoted for the missing forwarding interface.

Refutation attempt: The peer-slot exception is correct and must remain. `LinkAttrsUp` handles carrier-down only after lookup succeeds, while readiness blocks promotion rather than reliably demoting an incumbent. There is no local-error recovery path in this branch.

HPC/invariant check: One monitor poll per second, never a packet-path operation. Feed the error into existing dampening so transient lookup failures do not create flapping.

Why it matters: A configured interface monitor can fail open precisely when its netdev disappears.

Fix direction: Record a local lookup failure as down through the existing debounce/state path, while preserving the peer-interface skip. Cover missing-at-start, disappearance while primary, and later reappearance.

Labels: ha, monitor, fail-open

Dedup note: Searched `interface.*monitor.*(missing|lookup)|monitor.*(missing|LinkByName)|LinkByName.*monitor`. The only nearby tracked entry is `#4480`, a display-status issue, not monitor-to-election behavior.

### C179-064: Monitor configuration replacement leaves removed failure weights active

Source IDs: A5-C003

Title: Monitor configuration replacement leaves removed failure weights active

Severity: Medium

Confidence: High

Evidence: `pkg/cluster/monitor.go:226`

```go
// UpdateGroups replaces the monitored redundancy groups.
func (mon *Monitor) UpdateGroups(groups []*config.RedundancyGroup) {
	mon.mu.Lock()
	defer mon.mu.Unlock()
	mon.groups = groups
}
```

Trace: `UpdateConfig` calls this replacement for surviving RGs. A down monitor previously populated `ifaceState`/`ipState`, `MonitorFails`, and `monitorWeights`; after removal it is no longer polled, so no up transition deletes the contribution. A changed weight while remaining down similarly never reaches `SetMonitorWeight`.

Refutation attempt: `UpdateConfig` clears `monitorWeights` only when an entire RG is deleted (`pkg/cluster/group_state.go:42-63`). `recalcWeight` intentionally trusts retained maps, and `TestMonitor_UpdateGroups` adds an RG but does not exercise removal, changed weight, or moved monitor state.

HPC/invariant check: Config-apply work is bounded by configured monitors. Reconciliation must not move any work to packet processing or heartbeat transmission.

Why it matters: A valid commit can leave a node permanently de-rated and secondary after the failed monitor was removed.

Fix direction: Diff old/new monitor identities while updating groups, delete obsolete states and weight contributions, update retained-down weights, and recalculate each affected RG once.

Labels: ha, config-reconcile, stale-state

Dedup note: Searched `monitor.*(removed|replace|reconcile|weight)|MonitorFails|monitorWeights`. The corpus contains monitor deadlock and configuration validation work, but no tracked stale-runtime-contribution root.

### C179-065: Manual failover batch reports success after partial supersession

Source IDs: A5-C004

Title: Manual failover batch reports success after partial supersession

Severity: Medium

Confidence: High

Evidence: `pkg/cluster/failover.go:536`

```go
		// A ResetFailover on this member during the unlocked window bumped
		// its failover generation — its reset wins; skip the SecondaryHold
		// write so we don't clobber it (#5246).
		if m.failoverGen[rgID] != batchGen[rgID] {
			slog.Info("cluster: manual failover batch member superseded by reset, skipping", "rg", rgID)
			continue
		}
		oldState := rg.State
```

Trace: `ManualFailoverBatch` releases the manager lock for per-RG pre-hooks, then loops over members after reacquisition. A reset or removal of one RG takes `continue`, but later RGs are still placed in `SecondaryHold` and the function returns nil despite its documented together/no-split handoff contract.

Refutation attempt: Generation checks correctly preserve the winning reset and locking prevents a data race. Neither property makes the multi-RG mutation atomic; no post-hook, all-member validation occurs before the first state write.

HPC/invariant check: Manual control path. The invariant is one commit decision for the normalized RG set, not per-member best effort.

Why it matters: A success response can leave paired RGs in split ownership, breaking a full dataplane handoff.

Fix direction: Revalidate existence and generation for every member before any mutation, then either commit all or fail the batch as superseded. Test blocked pre-hook reset/removal of one member.

Labels: ha, failover, transactionality

Dedup note: Searched `ManualFailoverBatch|failover.*batch.*(partial|atomic|reset)|failoverGen`; no prior batch-partial-commit issue was found.

### C179-066: Failed peer failover has no remote transfer-out abort

Source IDs: A5-C005

Title: Failed peer failover has no remote transfer-out abort

Severity: High

Confidence: High

Evidence: `pkg/cluster/failover.go:281`

```go
	if err := m.commitRequestedPeerFailover(rgID, reqID); err != nil {
		return err
	}
	if localCommitReadyFn != nil {
		if err := localCommitReadyFn([]int{rgID}); err != nil {
			m.abortRequestedPeerFailover(rgID, reqID)
			return err
		}
	}
```

Trace: The remote daemon handles phase one by calling `ManualFailover` (`pkg/daemon/daemon_ha_sync.go:672-681`) before it acknowledges. A local readiness or commit failure calls `abortRequestedPeerFailover`, which only restores this manager's `peerGroups` snapshot; `syncMsg*` defines request, ack, commit, and commit-ack but no abort. The remote remains `SecondaryHold` until an unrelated recovery/reset condition.

Refutation attempt: Request IDs, remote-primary validation, and the local restore prevent several stale/duplicate errors. They do not contact the manager that has already demoted itself. The two-second both-yield deadlock escape is not a rollback protocol and does not cover a requester that remains ineligible.

HPC/invariant check: Explicit HA transfer control path. A failed command must leave neither participant committed to a new role without a deterministic terminal outcome.

Why it matters: A failed requested failover can blackhole service by leaving the prior owner demoted while the requester cannot assume ownership.

Fix direction: Add a request-ID-scoped abort/rollback message with a remote snapshot, or make phase one a non-demoting prepare and fence demotion at commit. Exercise two managers over a real transport for every post-phase-one failure.

Labels: ha, failover, distributed-transaction

Dedup note: Searched `failover.*(abort|rollback|cancel)|transfer.*(rollback|abort)|secondary.?hold`. `#390/#397` track request/commit handoff and heartbeat preservation; their existing fix locus is the commit protocol, while no remote abort message or handler exists.

### C179-067: Event-stream bulk markers can overtake queued sessions and claim an empty authoritative set

Source IDs: A5-C006

Title: Event-stream bulk markers can overtake queued sessions and claim an empty authoritative set

Severity: High

Confidence: High

Evidence: `pkg/cluster/sync_bulk.go:21`

```go
	if s.BulkSyncOverride != nil {
		slog.Info("cluster sync: using bulk sync override (event stream)")
		if err := s.BulkSyncOverride(); err != nil {
			slog.Warn("cluster sync: bulk sync override failed, falling back", "err", err)
			return s.BulkSync()
		}
		// Send empty BulkStart/BulkEnd so the peer completes the
		// bulk receive handshake. Sessions were already delivered as
		// incremental updates via the event stream.
		return s.sendBulkMarkers()
```

Trace: The event callback calls void `QueueSessionV4/V6`, whose non-blocking queue can reject an entry; success from the helper only proves event delivery to Go. `sendBulkMarkers` writes directly under `writeMu`, whereas queued sessions are written by `sendLoop`, so markers can win the lock and produce BulkEnd before queued traffic. BulkEnd releases sync hold; moreover `reconcileStaleSessions` explicitly skips any empty bulk, so a real fallback export with zero sessions cannot clear stale peer sessions.

Refutation attempt: `writeMu` prevents byte interleaving, not FIFO ordering across the direct-marker and `sendCh` producers. The normal `BulkSync` writes session records between markers, and queue overflow enables a future sweep, but old pre-sweep sessions and the immediate completion barrier are not repaired by that eventual best effort.

HPC/invariant check: Bulk/control path only. A single ordered barrier after the final queued event is sufficient; do not add per-session synchronous waits.

Why it matters: The standby can be declared ready before its session table is complete, or retain stale sessions when a genuinely empty authoritative fallback is sent.

Fix direction: Put markers on the ordered stream or queue and await a sequence barrier before BulkEnd; encode marker-only/non-authoritative state separately; propagate queue-admission failure to the exporter. Test blocked queue, saturation, zero-session fallback, and large export.

Labels: ha, session-sync, bulk, ordering

Dedup note: Searched `event.*stream.*bulk|bulk.*event.*stream|sendBulkMarkers|bulk.*(ordering|empty)`. `#418` introduced event-stream bulk replay, but it does not cover the cross-producer ordering or empty-authority ambiguity.

### C179-068: Surviving session-sync daemon does not re-prime a rebooted peer

Source IDs: A5-C007

Title: Surviving session-sync daemon does not re-prime a rebooted peer

Severity: High

Confidence: High

Evidence: `pkg/cluster/sync_conn.go:546`

```go
		if coldStart {
			slog.Info("cluster sync: starting bulk sync on cold start", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
			if err := s.doBulkSync(); err != nil {
				slog.Warn("cluster sync: bulk sync failed", "err", err, "fabric", fabricIdx)
			}
		} else {
			slog.Info("cluster sync: skipping bulk sync on reconnect (already primed)", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
		}
```

Trace: `coldStart` is `!bulkEverCompleted`, a sticky process-local flag (`pkg/cluster/sync_conn.go:538`). After the peer daemon restarts, its table and flag reset but the survivor skips outbound bulk on reconnect. The restarted peer can send its own empty bulk, and `OnPeerConnected` re-pushes non-session state; old established sessions are not guaranteed to pass the incremental sweep's time filter.

Refutation attempt: The survivor-fabric redrive covers a bulk that was not acknowledged, not a completed prior bulk followed by peer state loss. A peer boot ID or handshake incarnation is absent, so a transport blip and a peer restart are indistinguishable to the survivor.

HPC/invariant check: Re-prime must occur only on an authenticated peer-incarnation change, preserving the deliberate avoidance of O(N) bulk on routine fabric flips.

Why it matters: Failover after a peer reboot can proceed with an empty or stale standby session table.

Fix direction: Exchange a process incarnation in the sync handshake and track outbound prime completion by peer incarnation. On change, send an authoritative bulk and test an old session surviving one node's reboot.

Labels: ha, session-sync, reboot, failover

Dedup note: Searched `bulk.*(reconnect|reboot|restart|re.?prime)|bulkEverCompleted|already primed`. `#466` intentionally suppresses routine reconnect bulk; this finding is the unmodeled peer-incarnation/state-loss case, not a request to undo that optimization.

### C179-069: Empty-table fast path can permanently suppress IPv6 GC discovery

Source IDs: A5-C008

Title: Empty-table fast path can permanently suppress IPv6 GC discovery

Severity: Medium

Confidence: High

Evidence: `pkg/conntrack/gc.go:253`

```go
	// Fast path: if no sessions existed on last sweep AND no new sessions
	// have been created since, skip the entire iteration.  This eliminates
	// ~25% CPU from empty-table batch lookups on idle firewalls.
	if gc.lastTotal == 0 && gc.telemetry != nil {
		newCtr, err1 := gc.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
		closedCtr, err2 := gc.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
		if err1 == nil && err2 == nil &&
			newCtr == gc.lastSessionCounter &&
			closedCtr == gc.lastClosedCounter {
			return gc.nextSweepDelay(0, false, false, 0, agingActive, earlyAgeout)
```

Trace: After a new IPv6-only session changes the global counter, one full sweep runs. Its v4 scan remains zero; with `lastV6Count == 0`, the first five full sweeps skip v6. It stores `lastTotal == 0`; later unchanged-counter ticks return before incrementing `sweepCount`, so the sixth forced v6 probe never occurs and the session is neither discovered nor expired.

Refutation attempt: The initial `lastV6Count` is `-1`, so first startup scans v6, but the described state arises after an empty scan. `SkipSweep` avoids this code only in userspace mode; it does not protect the BPF-map runtime. No per-family telemetry guard exists.

HPC/invariant check: This is a GC/control optimization. Keep the v4 fast path but advance or deadline the mandatory v6 probe even on a fast return.

Why it matters: An otherwise idle IPv6 flow can persist beyond its timeout and evade expiration callbacks.

Fix direction: Use per-family counters or a wall-clock v6 probe deadline independent of `sweepCount`. Test first IPv6 arrival after an empty scan with no later counter changes.

Labels: conntrack, gc, ipv6, aging

Dedup note: Searched `conntrack.*(v6|ipv6).*(gc|sweep)|lastV6|empty.table.*fast`; no prior conntrack GC root matched.

### C179-070: VRRP reconcile ignores advertise interval and GARP count changes

Source IDs: A5-C009

Title: VRRP reconcile ignores advertise interval and GARP count changes

Severity: Medium

Confidence: High

Evidence: `pkg/vrrp/manager.go:408`

```go
			// Check if config changed (and the live ifindex is unchanged).
			if !ifindexChanged &&
				existing.cfg.Priority == inst.Priority &&
				existing.cfg.Preempt == inst.Preempt &&
				existing.cfg.PreemptHoldTime == inst.PreemptHoldTime &&
				existing.cfg.TrackInterface == inst.TrackInterface &&
				existing.cfg.TrackPriorityCost == inst.TrackPriorityCost &&
				vipsEqual(existing.cfg.VirtualAddresses, inst.VirtualAddresses) {
				continue // No change.
```

Trace: `CollectInstances` supplies both fields, but a commit changing only either satisfies this predicate. No restart or `updateConfig` occurs; even that in-place function only copies priority/preempt/tracking fields (`pkg/vrrp/instance.go:473-490`). Existing timers, wire MaxAdvertInt, and GARP behavior retain the old configuration.

Refutation attempt: The periodic reconcile repeats the same incomplete equality test, so it cannot self-heal. A VIP or priority change later incidentally rebuilds/updates the instance, but that does not make the original successful commit effective.

HPC/invariant check: Reconciliation path only. Timer changes should be signaled safely to the run-loop or treated as restart-required, without packet-path work.

Why it matters: Cluster peers can run asymmetric advertised cadence or GARP behavior after a commit reported as applied.

Fix direction: Centralize complete instance equality, classify fields by in-place/restart safety, copy all in-place fields under `vi.mu`, and test every single-field mutation.

Labels: vrrp, config-reconcile, ha

Dedup note: Searched `VRRP.*(AdvertiseInterval|GARPCount)|UpdateInstances.*(interval|GARP)|advertise.*reconcile`; no tracked live-reconcile omission matched.

### C179-071: VRRP accepts a failed required IPv6 advertisement socket as ready

Source IDs: A5-C010

Title: VRRP accepts a failed required IPv6 advertisement socket as ready

Severity: High

Confidence: High

Evidence: `pkg/vrrp/instance.go:437`

```go
	// Open IPv6 raw socket if any VIPs are IPv6.
	if hasIPv6VIPs {
		v6Conn, v6FD, err := openIPv6Socket(vi.cfg.Interface, vi.iface, isVLAN)
		if err != nil {
			slog.Warn("vrrp: ipv6 socket open failed, IPv6 adverts disabled",
				"key", vi.key(), "err", err)
		} else {
			vi.ipv6Conn = v6Conn
			vi.ipv6FD = v6FD
			// Wrap the raw IPConn so we can attach an IPV6_PKTINFO
```

Trace: `openSocket` returns nil after this warning, so `UpdateInstances` installs and runs the instance. `RGVRRPReady` returns true merely when an RG instance is in the manager map (`pkg/vrrp/manager.go:661-679`); an IPv6 send with nil `ipv6Conn` returns nil, so an IPv6-only MASTER can claim role and VIP ownership without advertising it.

Refutation attempt: AF_PACKET can still receive IPv6 traffic, but it cannot send the missing raw IPv6 advertisements. IPv4 capability does not help an IPv6-only VRRP instance. The build-before-teardown guard only observes `openSocket`'s nil return.

HPC/invariant check: Socket setup/readiness path. Required configured-family send capability must be proven before an instance becomes eligible for promotion.

Why it matters: A split-master or blackhole can arise while takeover readiness falsely reports a usable VRRP instance.

Fix direction: Fail construction when a configured VIP family lacks a send socket, close already-open descriptors, preserve any old instance, and test IPv6-only and dual-stack failure cases.

Labels: vrrp, ipv6, readiness, ha

Dedup note: Searched `VRRP.*(IPv6|ipv6).*(socket|advert)|ipv6.*adverts.*disabled`. `#2155` covers IPv6 extension-header receive and `#2156` build-before-teardown on instance replacement; neither covers swallowed required-family send-socket failure.

### C179-072: VRRP emits role state without verified VIP ownership

Source IDs: A5-C011

Title: VRRP emits role state without verified VIP ownership

Severity: High

Confidence: High

Evidence: `pkg/vrrp/instance.go:1849`

```go
func (vi *vrrpInstance) becomeMaster() {
	pri := vi.getPriority()
	slog.Info("vrrp: transitioning to MASTER",
		"key", vi.key(), "priority", pri)
	vi.setState(StateMaster)
	vi.addVIPs()
	vi.sendAdvert(pri)
	vi.emitEvent()
	vi.garpEpoch.Add(1)
```

Trace: `addVIPs` and `removeVIPs` only log netlink/link/parse errors and return void. The daemon consumes MASTER events to make the RG active, remove blackholes, and start per-RG services (`pkg/daemon/daemon_ha.go:429-455`); BACKUP emits similarly after best-effort removal. Thus control-plane role may diverge from kernel VIP ownership in either direction.

Refutation attempt: `EEXIST` is a valid add success, but other errors are swallowed. The two-second reconciler re-reads VRRP state, not actual addresses, so it repeats the same false role. GARP tests and later best-effort reconciliation do not prove ownership before publication.

HPC/invariant check: Role-transition control path. A bounded netlink batch already exists; returning structured results adds no packet hot-path work.

Why it matters: Services and forwarding can activate without the VIP, or deactivate while the address remains locally owned, violating HA ownership fencing.

Fix direction: Return per-VIP operation outcomes, publish role only after required ownership is established, and on failure retry/fence/rollback. Inject link, parse, add, and delete failures through the daemon event consumer.

Labels: vrrp, vip, ownership, ha

Dedup note: Searched `VRRP.*VIP.*(fail|error)|becomeMaster.*VIP|AddrAdd.*VRRP`. Nearby `#3924` is userspace local-address pruning and `#2156` is replacement lifetime; neither validates VIP operations before role publication.

### C179-074: Session decoder installs an incomplete core record with zero-valued forwarding fields

Source IDs: A5-C013

Title: Session decoder installs an incomplete core record with zero-valued forwarding fields

Severity: Medium

Confidence: High

Evidence: `pkg/cluster/sync_protocol.go:354`

```go
	val.State = payload[off]
	off++
	val.Flags = payload[off]
	off++
	val.TCPState = payload[off]
	off++
	val.IsReverse = payload[off]
	off += 5
	if off+48 > len(payload) {
		return key, val, true
```

Trace: A framed v4 payload ending after the 24-byte key/state block, or in its following 48-byte mandatory block, returns `ok=true`. `handleMessage` rebases zero timestamps and sends the record to `installClusterSyncedV4`; the session store then accepts it as a peer-owned session. The v6 decoder has the equivalent early-success path.

Refutation attempt: Historical code intentionally describes this as length tolerance for older layouts, so the fix cannot simply require the newest payload length. However, no encoder shown in repository history emits a record that ends inside a block; known compatibility extensions are trailing complete blocks. The valid-empty/old-layout intent therefore does not justify accepting arbitrary mid-core truncation.

HPC/invariant check: Decoder/control path; accepted-layout checks are constant-time and allocation-free.

Why it matters: A malformed but fully framed session message can create an incorrectly zoned, timed-out, or NAT-incomplete flow on standby.

Fix direction: Define the finite set of complete historical core lengths, reject all mid-block lengths, and fuzz each truncation offset through `handleMessage` to prove no store update.

Labels: ha, session-sync, decoder, validation

Dedup note: Searched `truncat.*(session|payload|record)|partial.*session|decode.*session.*length`. Existing `#2170` documents intentionally length-gated trailing extensions; this root is acceptance inside a mandatory core block, which that compatibility discipline does not require.

### C179-075: Malformed DHCP full-set frame replaces held peer leases with an empty or prefix set

Source IDs: A5-C014

Title: Malformed DHCP full-set frame replaces held peer leases with an empty or prefix set

Severity: Medium

Confidence: High

Evidence: `pkg/cluster/sync_protocol.go:816`

```go
	for i := 0; i < count; i++ {
		if off+4 > len(payload) {
			break
		}
		recLen := int(binary.LittleEndian.Uint32(payload[off:]))
		off += 4
		if recLen < 0 || off+recLen > len(payload) {
			break
		}
		out = append(out, decodeOneLease(payload[off:off+recLen]))
```

Trace: A short payload yields nil and a count mismatch yields its complete prefix. The receive cases unconditionally call `storePeerDHCPLeases` after decode (`pkg/cluster/sync_conn.go:1569-1583`), replacing the authoritative full set and its receive timestamp. On takeover, missing leases can no longer be seeded and may be reallocated.

Refutation attempt: `io.ReadFull` protects the outer frame but not its internal count/record grammar. The decode behavior is deliberately tested for truncated-prefix acceptance, so this is not an unreachable error path. An authenticated transport lowers hostile injection risk, but authentication is optional and trusted peer bugs still must not destroy an authoritative replacement set.

HPC/invariant check: Infrequent control message. Full count/record validation is bounded by the decode already performed.

Why it matters: DHCP HA can lose lease knowledge and allocate addresses that remain in use after failover.

Fix direction: Return `(leases, error)`, require exact count consumption and complete records, distinguish valid zero count from malformed input, and retain old state/timestamp on error.

Labels: ha, dhcp, session-sync, decoder

Dedup note: Searched `truncat.*(lease|payload|record)|partial.*lease|DHCP.*full.set`. `#2239` introduced the lease codec and bounded its allocation; no existing issue covers committing malformed full-set prefixes.

### C179-076: IP-monitor status fabricates monitor sections and hides healthy probes

Source IDs: A5-C015

Title: IP-monitor status fabricates monitor sections and hides healthy probes

Severity: Low

Confidence: High

Evidence: `pkg/cluster/status.go:536`

```go
		// Show IP monitor section regardless (config-driven).
		_ = mon // monitor has the config but we show from state
		if len(ipFails) > 0 || true {
			// We always show the section for each RG if any monitors are configured.
			fmt.Fprintf(&b, "Redundancy group %d:\n", rg.GroupID)
			if len(ipFails) > 0 {
				for _, f := range ipFails {
					addr := strings.TrimPrefix(f, "ip:")
					fmt.Fprintf(&b, "  %-20s Status: unreachable\n", addr)
```

Trace: `|| true` sets `hasIP` for every configured RG state, so the no-monitor branch cannot execute. Since the formatter only examines failure names and ignores `mon`, configured healthy targets are also indistinguishable from no configured targets.

Refutation attempt: This is not cosmetic wording: the formatter obtains the monitor pointer but discards it, and no caller filters states to monitored RGs. The output cannot satisfy its own per-probe-status contract.

HPC/invariant check: CLI/status only; no packet-path impact.

Why it matters: Operators cannot distinguish an unconfigured RG from a healthy monitored RG during HA diagnosis.

Fix direction: Snapshot configured targets and their current monitor state, render none/healthy/unreachable/mixed accurately, and add formatter tests.

Labels: ha, status, observability

Dedup note: Searched `IP monitoring.*status|No IP monitoring|ip monitoring.*configured`; no prior matching formatter defect was found.

### C179-077: HA status reports outbound bulk count as received bulk count

Source IDs: A5-C016

Title: HA status reports outbound bulk count as received bulk count

Severity: Low

Confidence: High

Evidence: `pkg/cluster/status.go:388`

```go
	if syncStats.DHCPLeasesSeeded > 0 {
		fmt.Fprintf(&b, "    %-32s %-12s %d\n", "DHCP leases seeded",
			"", syncStats.DHCPLeasesSeeded)
	}
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Bulk syncs",
		syncStats.BulkSyncs, syncStats.BulkSyncs)
	fmt.Fprintf(&b, "    %-32s %-12s %d\n", "Sessions installed",
		"", syncStats.SessionsInstalled)
```

Trace: `BulkSyncs` increments after local bulk/marker send in `sendBulkMarkers` and `BulkSync`; inbound completion uses receive state/timestamps instead. `FormatStatistics` and `FormatDataPlaneStatistics` both print the same outbound counter in Sent and Received, so an asymmetric exchange appears healthy.

Refutation attempt: Other rows use directional counters. There is no documented definition making `BulkSyncs` bidirectional, and the receive path has no increment of it. The second formatter reproduces rather than corrects the defect.

HPC/invariant check: CLI/status only; no packet-path impact.

Why it matters: Operators can incorrectly infer that a standby completed inbound bulk during incident triage.

Fix direction: Add an inbound bulk-completion counter and render each direction, or leave Received blank until that telemetry exists. Assert asymmetric output in both formatters.

Labels: ha, status, observability

Dedup note: Searched `Bulk sync.*(sent|received)|bulk.*count.*(status|display)|status.*BulkSync`; no existing directional-status issue matched.

### C179-078: Malformed session frames can be cumulatively ACKed away by later telemetry

Source IDs: A6-C001

Title: Malformed session frames can be cumulatively ACKed away by later telemetry

Severity: High

Confidence: High

Evidence: `pkg/dataplane/userspace/eventstream.go:396`
```go
		switch typ {
		case EventTypeSessionOpen, EventTypeSessionUpdate:
			delta, ok := decodeSessionEvent(payload)
			if !ok {
				es.DecodeErrors.Add(1)
				continue
			}
```

Trace: A complete but undecodable SessionOpen, Update, or Close at sequence N takes `continue`, preserving the old `prevSeq` and `lastAppliedSeq`. A valid lossy telemetry frame at N+1 only records a sequence gap, then `dispatchOrQueueDataplaneFrame` marks N+1 applied. `sendAckIfNeeded` ACKs that watermark, and `userspace-dp/src/event_stream/mod.rs:1326` trims replay entries through it, including the unapplied session frame. A subsequent session frame sees no gap because telemetry advanced `prevSeq`.

Refutation attempt: Oversize and truncated frames terminate the reader, and a subsequent session frame would invoke `handleSessionSyncGap`; neither guard covers a complete malformed session payload followed by valid telemetry. The full-resync callback is only reached for detected session gaps or explicit FullResync frames. The existing #2874 recovery therefore does not cover this decoder-rejection path.

HPC/invariant check: This is HA control-stream work, not packet-path work. The invariant is that the ACK watermark may cover only contiguous, successfully applied correctness-critical session state.

Why it matters: An open or close can be irreversibly discarded from the replay buffer, leaving the standby session view divergent until an unrelated full sync.

Fix direction: Treat decoding failure for every session-sync frame as a hard sync break: keep the watermark at N-1, trigger the bounded full-resync path, and close/reconnect. Test malformed N followed by valid telemetry N+1 for Open, Update, and Close.

Labels: bug, security, ha, session-sync, fail-closed

Dedup note: Searched `event.?stream|session.*(decode|malform|ack|replay|gap)`, `decodeSessionEvent`, `#2874`, and `#2959` in the corpus. #2874 covers a producer/replay sequence hole and #2959 validates impossible ACK ranges; this distinct root cause is local semantic decoder rejection being skipped and then cumulatively ACKed.

### C179-079: Shim preflight and verification omit production shared-map ABI contracts

Source IDs: A6-C002

Title: Shim preflight and verification omit production shared-map ABI contracts

Severity: High

Confidence: High

Evidence: `pkg/dataplane/loader_userspace_shim.go:327`
```go
func validateUserspaceShimLivePins(userspaceSpec *ebpf.CollectionSpec, readPin userspacePinnedMapABIReader) error {
	if readPin == nil {
		return nil
	}
	for _, name := range userspaceABICheckedPinnedMaps() {
		ms, ok := userspaceSpec.Maps[name]
		if !ok {
			continue // absent from the new shim: PinByName never loads it
		}
```

Trace: `userspaceABICheckedPinnedMaps` derives only from `userspacePinnedShimMaps` (`loader_userspace_shim.go:404`), which omits standalone shared maps such as `sessions`, `sessions_v6`, HA/counter maps, and `dnat_table_v6`. The live-pin check consequently cannot compare their current ABI. Independently, `validateUserspaceShimSpecWith` has an expected-shape arm only for v4 `dnat_table`, while production replaces both v4 and v6 maps (`loader_userspace_shim.go:122`). `verify_userspace_shim.go:111` creates the candidate's anonymous maps, so it does not exercise the production v6 replacement. A changed shared-map or embedded v6 ABI can pass verification, then fail with `ErrMapIncompatible` only after the old dataplane is stopped.

Refutation attempt: v4 `dnat_table` is checked against both the embedded spec and its live pin, and `userspace_fallback_stats` is intentionally disposable. `userspaceRequiredShimPins` includes shared pins only after collection loading and is presence-only. None of those protections covers the omitted state-bearing map family or verifies `dnat_table_v6` against the Go replacement contract.

HPC/invariant check: This is startup/deploy work. The invariant is that every production PinByName map and MapReplacement is preflighted using the same Type, KeySize, ValueSize, MaxEntries, and Flags contract that production load uses.

Why it matters: The advertised pre-stop gate can approve an upgrade that cannot load after the working daemon is stopped, stranding a node fail-closed and risking HA capacity loss.

Fix direction: Make one production replacement inventory drive embedded-spec validation, live-pin ABI checks, and verify-only replacements. Include every `userspaceShimSharedMapSpecs` entry, including `dnat_table_v6`, while retaining the explicit disposable-map exception. Add stale-live-pin and candidate-drift tests for state, HA, per-CPU counter, and v6 DNAT maps.

Labels: bug, upgrade-safety, abi, pinned-maps, availability

Dedup note: Searched `live.?pin|map.*ABI|ErrMapIncompatible|shared map`, `dnat_table_v6.*(verify|ABI|replacement|drift)`, `userspaceABICheckedPinnedMaps`, and `#5307`/`#2406`. #5307 strengthened field comparison for the included collection map set; #2406 added v6 steering. The residual root is the incomplete inventory that excludes production shared/replacement maps altogether. A6-b3-F004 is merged because it is the v6 manifestation of that same inventory defect.

### C179-080: Clear-all leaves userspace global-counter offsets visible

Source IDs: A6-C003

Title: Clear-all leaves userspace global-counter offsets visible

Severity: Medium

Confidence: High

Evidence: `pkg/dataplane/maps_counters.go:152`
```go
func (m *Manager) ClearGlobalCounters() error {
	zm, ok := m.maps["global_counters"]
	if !ok {
		return fmt.Errorf("global_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]uint64, numCPUs)
	for i := uint32(0); i < GlobalCtrMax; i++ {
		if err := zm.Update(i, zero, ebpf.UpdateAny); err != nil {
```

Trace: Status polling adds helper deltas to `userspaceCounterOffsets`, and `ReadGlobalCounter` adds that map to the BPF per-CPU total. `userspace.Manager.ClearAllCounters` invokes this method, which resets only the BPF array. No caller clears the offset map, while `prevBindingCounters` prevents old helper totals from being replayed as new deltas; the historical offset therefore remains visible indefinitely.

Refutation attempt: `ClearZoneCounterOffsets` and NAT clear paths show that separate userspace mirrors are intentionally cleared elsewhere. Searches of all `userspaceCounterOffsets`, `IncrementGlobalCounter`, and `ClearGlobalCounters` references found no global-offset reset. The helper IPC clears policy/NAT/zone stores, not this Go-only delta map.

HPC/invariant check: The offset exists to avoid a per-CPU BPF read-modify-write race. Resetting it under its existing mutex is cold-path O(1) work and must not reset the helper delta baseline.

Why it matters: A successful clear-all leaves global traffic, drop, policy, screen, host-inbound, SYN-cookie, and NAT64 statistics nonzero, invalidating operational baselines.

Fix direction: Add a locked global-offset clear and execute it as part of clear-all after the BPF clear succeeds; serialize it with the userspace manager's status bridge. Test a seeded offset, clear, and subsequent higher helper cumulative total.

Labels: bug, observability, counters, clear-semantics

Dedup note: Searched `global counter|counter offset|clear all counter`, `userspaceCounterOffsets`, `ClearGlobalCounters`, and `counter.*snap.?back`. The corpus covers NAT/zone snap-back and population work, not omission of the global in-memory offset clear.

### C179-081: NAT counter collision fallback makes rule IDs encounter-order dependent

Source IDs: A6-C004

Title: NAT counter collision fallback makes rule IDs encounter-order dependent

Severity: Low

Confidence: High

Evidence: `pkg/dataplane/compiler_nat.go:134`
```go
	// Derive the stable id; resolve the rare distinct-key collision against the
	// ids already assigned in this compile by deterministic re-hash.
	counterID := natCounterIDForKey(ruleKey)
	for attempt := 1; natCounterIDInUse(result, ruleKey, counterID); attempt++ {
		counterID = natCounterIDForKey(fmt.Sprintf("%s#%d", ruleKey, attempt))
		if counterID == 0 {
			counterID = 1
		}
	}
```

Trace: The first colliding key retains the base FNV-1a ID; only the later key is suffixed. `snat/rs/rule-91588` and `snat/rs/rule-154876` both hash to `3928167816`; their `#1` forms both hash to `487396352`. Reordering the rules swaps those numeric IDs, so the helper's numeric-keyed cumulative totals switch rule attribution.

Refutation attempt: The 256-rule cap makes accidental collisions rare, but the concrete valid names reproduce one. The collision code contains no sort or persisted allocator, and existing reorder tests use non-colliding names. The claimed identity-only guarantee is therefore false on this reachable branch.

HPC/invariant check: This is cold compilation/publication work. The remedy must preserve the zero runtime lookup cost of numeric counter IDs.

Why it matters: A harmless configuration reorder can misstate cumulative NAT translation totals for the two colliding rules.

Fix direction: Allocate from a deterministically sorted complete key set before emitting rules, or persist a full-key allocation. Add forced-collision reorder and removal/re-add tests using the verified pair.

Labels: bug, observability, nat, deterministic-compilation

Dedup note: Searched `NAT counter.*collision|counter ID.*collision`, `assignNATCounterID`, `natCounterIDForKey`, and `#2255`. #2255 introduced identity-stable attribution; it does not address its collision fallback assigning the winner by encounter order.

### C179-082: Candidate XDP attachments can diverge from the last acknowledged snapshot

Source IDs: A6-C005

Title: Candidate XDP attachments can diverge from the last acknowledged snapshot

Severity: High

Confidence: High

Evidence: `pkg/dataplane/userspace/manager_compile.go:184`
```go
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	result, err := m.bpfShim.CompileUserspaceShim(cfg)
	if err != nil {
		return nil, err
	}
	ucfg := deriveUserspaceConfig(cfg)
	activeState := m.policySchedulerActiveStateSnapshot()
	// #1827: include the cached ip-monitoring route overlay so a full
	// apply (operator commit) while a policy is FAILED preserves the
```

Trace: `CompileUserspaceShim` calls `attachUserspaceShimXDP` before this function builds the userspace snapshot. After successful build, `syncInterfaceAttachments` can detach links absent from the candidate set before bootstrap, process, protocol, or `apply_snapshot` failures. `lastSnapshot` advances only after a successful `apply_snapshot`; none of the error paths restores the old XDP link set, so kernel attachment state need not match the helper's retained snapshot.

Refutation attempt: The userspace-shim compiler suppresses legacy map writes, so a newly attached candidate interface may fail closed rather than receive candidate policy; that does not restore the required attachment/snapshot correspondence. The old-interface detach after snapshot construction is sufficient to create a bypass/outage boundary when later publication fails. No rollback or error-path reapply of the prior attachment set exists.

HPC/invariant check: XDP attachment is a packet admission boundary. The invariant is an atomic correspondence between live attachments and the acknowledged helper snapshot; staging can remain entirely off the packet path.

Why it matters: A failed apply can leave a formerly protected ingress without the shim or leave an unacknowledged ingress attached, producing a policy bypass or availability fault inconsistent with the reported retained snapshot.

Fix direction: Build and validate first; stage candidate additions, acknowledge the snapshot, then remove obsolete links. On every later failure, remove new links and restore the prior set. Test failures after build, bootstrap, protocol checks, and `apply_snapshot`.

Labels: transactionality, xdp, control-plane, rollback

Dedup note: Searched `manager_compile|CompileUserspaceShim|syncInterfaceAttachments`, `apply_snapshot.*(fail|rollback|attach)`, and `XDP attachment.*(rollback|transaction)`. Existing publication issues concern helper state, not kernel attachment mutation before snapshot commit.

### C179-083: Mandatory userspace control disable errors are discarded before worker teardown

Source IDs: A6-C006

Title: Mandatory userspace control disable errors are discarded before worker teardown

Severity: High

Confidence: High

Evidence: `pkg/dataplane/userspace/process_linkcycle.go:19`
```go
	// Read current ctrl, set enabled=0, write back.
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		return
	}
	ctrl.Enabled = 0
	_ = ctrlMap.Update(zero, ctrl, ebpf.UpdateAny)
	slog.Info("userspace: disabled ctrl (helper stopping)")
```

Trace: `PrepareLinkCycle` and `stopLocked` invoke this void helper, then stop workers or the helper regardless of lookup/update success. With a stale enabled control row and READY bindings, the XDP shim keeps redirecting until heartbeat expiry; after worker/UMEM teardown those redirects target dead XSK resources.

Refutation attempt: The shim's ctrl-disabled gate is correctly fail-closed, but this path never establishes that gate. No alternate stop path clears bindings or detaches XDP first. Stronger map-sync helpers elsewhere return errors but are not used by lifecycle teardown.

HPC/invariant check: No packet may be redirected after its worker/UMEM lifetime ends. Checked cold-path map I/O and readback add no forwarding-path cost.

Why it matters: A transient map failure during shutdown or a link cycle can create up to a heartbeat-timeout transit outage and violate the required UMEM quiescence ordering.

Fix direction: Return and propagate disable errors, use a checked fail-closed fallback when lookup fails, and verify the resulting row before worker teardown. If forced shutdown continues, explicitly detach or clear all bindings. Add lookup, update, and readback fault-injection tests.

Labels: af-xdp, lifecycle, fail-closed, bpf-map, outage

Dedup note: Searched `disableUserspaceCtrlLocked`, `stop_workers.*ctrl`, `ctrl.*(disable|enabled).*helper`, `dead.*XSK`, and `heartbeat.*dead`. The corpus has binding and heartbeat work but no teardown path that discards the mandatory ctrl-map failure.

### C179-084: Standalone HA-state cleanup failure has no convergence retry

Source IDs: A6-C007

Title: Standalone HA-state cleanup failure has no convergence retry

Severity: High

Confidence: High

Evidence: `pkg/dataplane/userspace/manager_compile.go:360`
```go
		if err := m.syncHAStateLocked(); err != nil {
			return result, fmt.Errorf("publish userspace HA state: %w", err)
		}
	} else if err := m.clearHelperHAStateLocked(); err != nil {
		// Non-cluster node: ensure neither the manager nor the helper retains
		// HA groups. seedHAGroupInventoryLocked already cleared m.haGroups
		// above; this also clears any groups a prior clustered apply pushed to
		// the helper (cluster->standalone live reconfig), which would otherwise
		// keep the HAInactive transit-drop gate armed (Codex review #1928 Q3).
		return result, fmt.Errorf("clear userspace HA state: %w", err)
```

Trace: A cluster-to-standalone apply acknowledges the new snapshot before this empty `update_ha_state`. If that request fails, the helper retains old HA groups while the manager has set `clusterHA=false`. The existing status loop skips HA sync for non-cluster mode; a newly started helper has not yet reached `ensureStatusLoopLocked`. The empty update is therefore not retried, and the nonempty helper map causes owner-RG-zero forwarding candidates to remain HAInactive.

Refutation attempt: `clearHelperHAStateLocked` is idempotent and the helper rebuilds its map only after a successful request, confirming that failure leaves stale groups. Snapshot retry logic checks unpublished snapshot generation, but this snapshot is already published. No standalone cleanup debt or status-loop retry exists.

HPC/invariant check: `standalone => helper ha_state is empty` is a packet-time invariant, but retrying its idempotent control RPC is cold-path work.

Why it matters: One transient control-socket error after a successful reconfiguration can leave standalone transit forwarding disabled until an unrelated full apply.

Fix direction: Record standalone-clear debt before returning and retry empty HA publication until status reports zero groups; treat the post-ack HA update as explicit convergence state. Test a successful snapshot followed by one failed empty update.

Labels: ha, convergence, retry, fail-closed, control-socket

Dedup note: Searched `clearHelperHAState`, `cluster.*standalone.*HA`, `HAInactive.*standalone`, `update_ha_state.*empty`, and `#1928`. #1928 fixed fabrication of HA groups on standalone applies; this residual is persistence after the explicitly required cleanup RPC fails.

### C179-085: Fabric publication failures are converted to successful refreshes

Source IDs: A6-C008

Title: Fabric publication failures are converted to successful refreshes

Severity: Medium

Confidence: High

Evidence: `pkg/dataplane/userspace/manager_ha.go:108`
```go
	var status ProcessStatus
	req := ControlRequest{
		Type:    "update_fabrics",
		Fabrics: fabrics,
	}
	if err := m.requestLocked(req, &status); err != nil {
		slog.Debug("userspace: failed to sync fabric state", "err", err)
	}
```

Trace: After the BPF fabric entry receives a new peer MAC, the controller calls this void method and returns nil; the daemon's refresh then returns true. On request failure, the helper retains its stale fabric view, no debt is recorded, and fast retry stops. The periodic refresh is the only later repair path.

Refutation attempt: The BPF update succeeds independently and the periodic refresh bounds the stale interval, but neither proves helper convergence. The interface itself makes success unobservable, and there is no acknowledgement or dirty-state state machine elsewhere.

HPC/invariant check: Fabric MAC/egress publication is cold control-plane work. The helper's fabric state must converge before callers declare the resolution refresh successful.

Why it matters: Cross-chassis traffic can use a stale fabric L2 destination for an entire refresh interval during a failover or failback window.

Fix direction: Return and propagate errors through the HA controller, retain dirty fabric state after a failed request, and retry with backoff until acknowledged. Test error propagation and convergence retry.

Labels: ha, fabric, error-propagation, convergence

Dedup note: Searched `SyncFabricState`, `update_fabrics`, `fabric.*(stale|retry|swallow)`, and `fabric MAC.*helper`. Existing fabric work covers state construction and steering, not silent loss of the helper publication error.

### C179-086: Invalid static-NAT host ports widen into whole-address mappings

Source IDs: A6-C009

Title: Invalid static-NAT host ports widen into whole-address mappings

Severity: High

Confidence: High

Evidence: `pkg/dataplane/userspace/nat_static.go:41`
```go
			out = append(out, StaticNATRuleSnapshot{
				Name:                 rule.Name,
				FromZone:             rs.FromZone,
				FromInterface:        rs.FromInterface,
				FromRoutingInstance:  rs.FromRoutingInstance,
				SourceAddresses:      sourceAddrs,
				ExternalIP:           rule.Match,
				InternalIP:           rule.Then,
				MatchDestinationPort: clampPort(rule.MatchDestinationPort),
```

Trace: Lenient load/peer-sync retains an invalid nonzero host port and `clampPort` converts it to zero. Rust's host-rule builder maps `(match_destination_port == 0, any mapped_port)` to `(None, None)` (`static_nat.rs:422`), stores it in the whole-address bucket, and DNAT lookup falls back to that bucket for every destination port. The mapped-port-without-match regression test explicitly verifies an all-port address translation.

Refutation attempt: Strict commit validation rejects invalid ports, and Rust correctly drops port-bearing block NAT. Neither applies to the documented lenient host-rule path; `clampPort` destroys the distinction between unset zero and invalid nonzero before Rust can reject it.

HPC/invariant check: This is snapshot compilation. A failed narrowing constraint must become never-match/drop, never the `None` wildcard used by the packet lookup table.

Why it matters: A malformed legacy or peer-synced port-forward can expose every service on the internal address through static DNAT and broad reverse SNAT.

Fix direction: Preserve invalidity through lowering or reject the whole host rule whenever a configured nonzero port is out of range or the port pair is incoherent. Add a lenient compile-to-Rust off-port no-match test.

Labels: security, dataplane, static-nat, fail-open

Dedup note: Searched `static.?nat.*(clamp|port|whole.?address|invalid|out.?of.?range)`, `clampPort`, `match_destination_port.*0`, `#2491`, and `#3202`. #2491 implements valid port forwarding and #3202 rejects port-bearing block NAT; neither covers invalid host ports collapsing into the whole-address sentinel.

### C179-087: Same-version old helpers silently narrow multi-zone global denies

Source IDs: A6-C010

Title: Same-version old helpers silently narrow multi-zone global denies

Severity: High

Confidence: High

Evidence: `pkg/dataplane/userspace/policies_lower.go:208`
```go
		// #3148/#4626: a global policy keeps fromZone/toZone == "junos-global"
		// (preserving global-tier classification + ordering) and carries its
		// optional zone SCOPE out-of-band in these fields. The singular fields
		// carry the first zone for backward compatibility with an old helper
		// during a rolling upgrade; the plural fields carry the full set. For a
		// zone-pair policy pol.Match.FromZones/ToZones are empty, so this is
		// inert.
		MatchFromZone:  config.ScopeSingular(pol.Match.FromZones),
		MatchToZone:    config.ScopeSingular(pol.Match.ToZones),
		MatchFromZones: pol.Match.FromZones,
```

Trace: New Go sends a plural zone set plus only its first element in the legacy singular field. The pre-#4626 helper at `a44209f8f^` has `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 3`, parses only the singular field, and ignores the additive JSON fields. Current Go and Rust still report version 3, so the protocol gate accepts that helper. A global deny scoped to `[dmz trust] -> untrust` therefore becomes only `dmz -> untrust` on the old helper.

Refutation attempt: Current helpers correctly prefer plural fields, and strict config validation accepts the intended valid multi-zone form. The review reopened the pre-change helper and its version gate; there is no capability bit, version increment, or action-safe fallback to protect the stated rolling-upgrade case.

HPC/invariant check: This is a wire-contract invariant, not hot-path cost. A compatibility extension that changes deny/reject coverage must not be silently ignored under the same protocol version.

Why it matters: During daemon/helper skew, traffic from every scoped zone after the first can evade a configured global deny or reject.

Fix direction: Bump the snapshot protocol or add a helper capability and refuse unsafe publication. If compatibility is required, lower deny/reject scopes safely and permit scopes narrowly. Add old-helper decode/evaluation tests for both actions.

Labels: security, policy, version-skew, fail-open

Dedup note: Searched `scoped global.*(multi.?zone|plural|singular|old helper|version|skew)`, `match_from_zones`, `MatchFromZones`, and `#4626`. #4626 implements zone sets for current helpers; its additive-wire approach is the distinct cause of this same-version old-helper semantic narrowing.

### C179-088: Exact-unit host-inbound overrides merge admissions from a conflicting zone

Source IDs: A6-C011

Title: Exact-unit host-inbound overrides merge admissions from a conflicting zone

Severity: High

Confidence: High

Evidence: `pkg/dataplane/userspace/zones_override.go:133`
```go
			if strings.Contains(ref, ".") {
				// Logical unit ref: the most specific override. Merge (union) it
				// onto any physical-inherited set already on this unit key. Because
				// refs are walked sorted and a bare physical ref sorts before its
				// units, a same-zone physical expansion below has already run, so
				// this yields physical ∪ unit.
				out[ref] = mergeHostInboundTraffic(out[ref], hib)
				continue
			}
```

Trace: On a tolerated duplicate logical-unit ownership, `buildInterfaceZoneMap` chooses the first sorted zone. `buildInterfaceHostInboundMap` then visits both zones and unconditionally merges each exact-unit override into the same entry. The owner is used when interface snapshots and nft views are built, so that winning zone receives the union including the losing zone's admission tokens.

Refutation attempt: The physical-interface expansion has an explicit `zoneByIface[un] != zn` quarantine guard, and strict new commits reject ambiguous ownership. The exact-unit branch has no equivalent guard, while lenient load/peer-sync deliberately retains the shape; no later path filters the merged override.

HPC/invariant check: This is configuration lowering. Each effective interface host-inbound token set must come only from its authoritative zone owner.

Why it matters: A warned legacy/HA conflict can grant a management service such as SSH in the wrong security zone in both Rust and kernel host-inbound enforcement.

Fix direction: Apply the same owner predicate to exact-unit and physical-expansion overrides; quarantine absent or losing owners. Add a lenient two-zone conflict test covering InterfaceSnapshot and ZoneHostInboundView.

Labels: security, host-inbound, zones, lenient-load, fail-open

Dedup note: Searched `host.?inbound.*(override|interface).*(cross.?zone|multi.?owner|merge|union)`, `buildInterfaceHostInboundMap`, `physical.*unit.*override`, and `#3720`. #3720 fixed physical-to-unit precedence and guards only its physical expansion; this is the separate exact-unit branch that bypasses that guard.

### C179-089: Zone-counter clear races a status poll that can restore old totals permanently

Source IDs: A6-C012

Title: Zone-counter clear races a status poll that can restore old totals permanently

Severity: Medium

Confidence: High

Evidence: `pkg/dataplane/userspace/zonecounters.go:26`
```go
func (m *Manager) ClearZoneCounters() error {
	var errs []error
	if m.bpfShim != nil {
		if err := m.bpfShim.ClearZoneCounters(); err != nil {
			errs = append(errs, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
```

Trace: The local sparse offset is cleared before `m.mu` is held. The 1 Hz status loop can acquire that lock in between and absolutely restore pre-clear helper rows via `SetZoneCounterOffset`. The clear then empties Rust's store, whose status output is sparse; `recordHelperStatusLocked` only overwrites rows present in the status response, so the restored old row persists through empty future polls.

Refutation attempt: The lock order avoids a deadlock, but it also permits precisely this interleaving. `clearHelperZoneCountersLocked` records an empty response after a successful RPC, and the helper's `ZoneCounterStore::snapshot` intentionally omits zero rows; neither operation removes the restored Go key.

HPC/invariant check: The local mirror reset and helper reset/status epoch must be serialized. This is operator-frequency control work and adds no hot-path cost.

Why it matters: A successful zone-counter clear can leave CLI, REST, and Prometheus reporting historical traffic indefinitely, corrupting baselines and alert evidence.

Fix direction: Acquire `m.mu` before clearing the local mirror and clear/reconcile offsets after successful helper acknowledgement. Add a barrier test that injects one status sync in the former race window.

Labels: correctness, observability, concurrency, counters

Dedup note: Searched `(zone|NAT|policy).?counter.*clear.*(race|status poll|repopulate|snap.?back|mutex)`, `ClearZoneCounters`, `clear_zone_counters`, and `zone.*counter.*(stale|offset)`. #3643 documents the need to clear helper and Go totals; it does not cover the serialization gap plus sparse-status permanence.

### C179-090: Tagged RETH services resolve logical-unit suffixes instead of VLAN-ID netdevs

Source IDs: A7-C001

Title: Tagged RETH services resolve logical-unit suffixes instead of VLAN-ID netdevs

Severity: High

Confidence: High

Evidence: pkg/daemon/daemon_ra.go:92
~~~go
	// Resolve RETH interface names for RA senders (needs real Linux names).
	for _, ra := range result {
		ra.Interface = config.LinuxIfName(cfg.ResolveReth(ra.Interface))
	}

	return result
~~~

Trace: With reth1 unit 3 vlan-id 100, configuration references use reth1.3 while Linux creates the selected physical member's .100 device. ResolveReth changes only the base and preserves .3, so RA, HA DHCP, and proactive neighbor paths target a nonexistent .3 link. The HA inventory independently enumerates unit.VlanID and therefore filters those entries against .100. During RETH MAC recovery, the daemon parses 100 from the real link and passes it to rethUnitHasIPv6, which indexes Units[100] even though the configured unit is Units[3], suppressing link-local restoration.

Refutation attempt: I inspected Config.ResolveKernelIfName, ResolveReth, rethInterfacesForRG, the RA manager lookup, DHCP filtering, and proxy-ARP tests. ResolveKernelIfName explicitly indexes the logical unit and emits unit.VlanID; the proxy-ARP unit-3/VLAN-100 test confirms that contract. The DHCP fixture makes unit and VLAN suffix equal and therefore does not cover the mismatch. No compiler validation requires the two numbers to match.

HPC/invariant check: This is commit and transition-time name resolution, not packet-path work. Every service must use one config-reference-to-kernel-name contract.

Why it matters: A valid tagged RETH can deterministically lose RA, link-local NDP, HA DHCP service, and proactive next-hop work at boot and failover.

Fix direction: Replace bare ResolveReth call sites with ResolveKernelIfName. For link-local repair, map the observed VLAN ID back to its logical unit or iterate configured units. Add a shared unit-3/VLAN-100 runtime matrix.

Labels: daemon, linux-networking, reth, vlan, ha, ipv6, dhcp

Dedup note: Searched the corpus for ResolveKernelIfName, ResolveReth, logical-unit/VLAN-ID synonyms, tagged RETH, RA, DHCP, and link-local recovery. #1565 and the prior interface-show finding cover API/display translation, while #3010 covers proxy-ARP. Neither covers these runtime service consumers or the VLAN-ID-as-unit-key failure.

### C179-091: Device-map preflight fails open when local NIC inventory is unavailable

Source IDs: A7-C002

Title: Device-map preflight fails open when local NIC inventory is unavailable

Severity: High

Confidence: High

Evidence: pkg/daemon/device_map.go:473
~~~go
	nics, err := enumeratePresentNICsFn()
	if err != nil {
		// Cannot enumerate hardware — do not block the commit on a
		// transient sysfs error; the #1922 lifeline is the backstop.
		slog.Warn("device-map pre-flight: NIC enumeration failed; skipping (lifeline still protects mgmt)", "err", err)
		return nil
	}
~~~

Trace: A candidate can move the live management NIC to a non-management name without assigning another NIC a protected name. When inventory works, deviceMapStrandsManagement rejects it. A transient inventory error instead returns nil to bootstrap, plain-commit, and confirmed-commit callers, allowing promotion without validating either the candidate or rollback target. A later boot calls applyStartupNamingPolicy, which dispatches directly to enumerateAndRenameMapped and performs the now-readable unsafe binding without rerunning the strand detector.

Refutation attempt: I inspected all preflight callers, the startup branch, deviceMapStrandsManagement, protected-name handling, and enumerateAndRenameMapped. The protected set prevents stale-file scrubbing and unmapped teardown; it does not veto an explicit mapped rename in phase 2. The existing tests prove the unsafe topology is detectable only when inventory is available. The #1922 lifeline is therefore not a substitute for this skipped topology decision.

HPC/invariant check: This is a cold commit/boot hardware scan. Failing closed on unknown inventory has no forwarding-path cost.

Why it matters: A momentary sysfs or netlink failure can turn a deterministic rejection into a durable management-lockout configuration that takes effect at reboot, including for confirmed commits.

Fix direction: Return inventory errors from local preflight and require retry. If passive HA admission must remain tolerant, record a reboot-inhibit health debt until a local hardware/config digest is validated. Add injected inventory-failure tests for all commit modes and startup.

Labels: daemon, device-map, management, fail-open, availability, ha

Dedup note: Searched device-map enumeration, preflight skip, management strand, lifeline, #1922, #1956, and #4884. #4884 is non-PCI inventory coverage, #1956 implements the detector, and #1922 protects a known lifeline. None records enumeratePresentNICsFn error being converted to successful admission followed by unchecked startup apply.

### C179-092: Device-map teardown loses networkd reload retry debt

Source IDs: A7-C003

Title: Device-map teardown loses networkd reload retry debt

Severity: Medium

Confidence: High

Evidence: pkg/daemon/device_map.go:684
~~~go
		if err := os.Remove(filepath.Join(linkDir, fname)); err == nil {
			reloaded = true
			slog.Info("device-map teardown: removed stale .link", "file", fname)
		}
		netFile := linkPrefix + target + ".network"
		if err := os.Remove(filepath.Join(linkDir, netFile)); err == nil {
			reloaded = true
			slog.Info("device-map teardown: removed stale .network", "file", netFile)
		}
~~~

Trace: After rename-back succeeds, teardown removes the managed .link and .network markers and only then calls networkctl reload. If that direct reload fails, the current apply returns an error but the files that identified pending activation are already gone. The subsequent networkd.Manager.Apply sees no desired-file delta and did not execute the failed reload, so its reloadPending bit is unset. An identical retry can skip activation and report success while networkd still has stale state.

Refutation attempt: I inspected the caller ordering, networkd.Manager.Apply, reloadPending, and the #5309 teardown tests. Manager debt is set only for reloads the manager executes. The reload-failure test asserts the error and call count but, unlike rename failure, does not assert retained durable state or an identical retry. No later path reconstructs this debt.

HPC/invariant check: Host activation must retain either durable desired-state evidence or an explicit pending bit until reload succeeds. This is apply-time work.

Why it matters: Stale addresses, routes, or ownership can remain active after a retry falsely reports convergence, until an unrelated networkd change or reboot.

Fix direction: Route teardown mutation through networkd.Manager or retain/restore a dedicated marker on reload failure. Test failure followed by byte-identical retry and require another reload before success.

Labels: daemon, device-map, networkd, transactional-apply, convergence

Dedup note: Searched #5309, device-map teardown/reload, networkctl reload, reloadPending, marker, and activation debt. #4954 implements debt inside networkd.Manager and #4956 covers startup naming reloads. This direct device-map reload bypasses that manager and destroys its own retry evidence, so its fix locus is distinct.

### C179-093: Shutdown leaves aggregator and IPsec rebind retry generations running

Source IDs: A7-C004

Title: Shutdown leaves aggregator and IPsec rebind retry generations running

Severity: Medium

Confidence: High

Evidence: pkg/daemon/daemon_ipsec_rebind.go:60
~~~go
func (d *Daemon) armIPsecRebind() {
	d.ipsecRebindMu.Lock()
	defer d.ipsecRebindMu.Unlock()
	d.ipsecRebindPending.Store(true)
	if d.daemonCtx == nil || d.ipsecRebindRetryActive {
		return
	}
	d.ipsecRebindRetryActive = true
	go d.ipsecRebindRetryLoop(d.daemonCtx)
}
~~~

Trace: Production Run receives a background daemonCtx that is documented as never cancelled. A failed DHCP-bound IPsec rebind starts a ticker on that context. Session aggregation separately starts on a child of context.Background and stores only aggCancel. Shutdown cancels the signal context and joins its WaitGroup, then explicitly stops scheduler and pin-retry generations, but never calls aggCancel and has no cancel/join owner for IPsec retry. The aggregator misses its cancellation flush, and IPsec retry can acquire applySem and invoke swanctl after dependent teardown.

Refutation attempt: I searched every aggCancel and ipsecRebindRetryActive reference and inspected Run defers, runShutdownSequence, and #5308 tests. Aggregator tests cancel in cleanup; IPsec tests provide a cancellable daemonCtx. Those are test-only owners. #5308 covers exactly scheduler and pin retry and provides no generic loop inventory or safety net for these two generations.

HPC/invariant check: Shutdown must cancel and join every goroutine before closing managers it can call. The event callback remains lock-free/O(1); orderly stop adds no hot-path work.

Why it matters: Normal stop discards the current reporting window, and persistent IPsec failures can race privileged control work against teardown or leak in embedded callers.

Fix direction: Give both generations private cancel and join state with a stopped latch. Invoke idempotent stop helpers before logging/IPsec dependency teardown and from early-return defers. Extend bounded #5308-style shutdown tests.

Labels: daemon, lifecycle, concurrency, shutdown, ipsec, observability

Dedup note: Searched aggCancel, aggregator shutdown/final flush, IPsec rebind retry, daemonCtx, #4899, #4964, and #5308. #4899 adds retry/health, #4964 fixes per-commit callback registration, and #5308 owns two other loops. None covers shutdown ownership for these generations.

### C179-094: Empty SSH known-host configuration preserves stale managed trust

Source IDs: A7-C005

Title: Empty SSH known-host configuration preserves stale managed trust

Severity: Medium

Confidence: High

Evidence: pkg/daemon/daemon_system.go:584
~~~go
// applySSHKnownHosts writes /etc/ssh/ssh_known_hosts from
// security { ssh-known-hosts { host ... } } config.
func (d *Daemon) applySSHKnownHosts(cfg *config.Config) {
	const path = "/etc/ssh/ssh_known_hosts"
	if len(cfg.Security.SSHKnownHosts) == 0 {
		return
	}
~~~

Trace: A nonempty configuration atomically replaces /etc/ssh/ssh_known_hosts with an xpfd-managed file. Removing the last host still invokes applySSHKnownHosts, but the zero-length guard exits before truncation or removal. OpenSSH continues consulting the old global keys, and every later empty apply repeats the same return.

Refutation attempt: I inspected the unconditional apply caller and all SSH tests. There is no boot or shutdown cleanup. Neighboring generated sshd/account artifacts have explicit empty-state removal, and this file carries a managed marker and is described as regenerated declarative state. External ownership therefore does not explain retaining xpfd's prior content.

HPC/invariant check: Empty desired trust must revoke previously managed trust anchors. This is cold host-file reconciliation.

Why it matters: A removed or rotated host key remains globally trusted, so possession of the retired private key can still satisfy host verification for system clients.

Fix direction: Remove a file bearing xpfd's ownership marker or atomically replace it with an empty managed file, surfacing errors. Add nonempty-to-empty, restart, and removal-failure tests.

Labels: daemon, ssh, host-integration, teardown, security

Dedup note: Searched applySSHKnownHosts, ssh_known_hosts, known-host stale/remove/empty, host trust, and SSH teardown synonyms. The corpus has SSH renderer and algorithm work but no generated global-known-host revocation root.

### C179-095: Passwd read errors permanently abandon removed-user credential revocation

Source IDs: A7-C006

Title: Passwd read errors permanently abandon removed-user credential revocation

Severity: High

Confidence: High

Evidence: pkg/daemon/login_password.go:125
~~~go
func lookupUIDGID(name string) (uid, gid int, ok bool) {
	data, err := os.ReadFile(passwdPath)
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
~~~

Trace: reconcileAbsentLoginUsers enumerates a provenance marker and calls deprovisionLoginUser. lookupUID delegates to lookupUIDGID, which maps any passwd read error to ok=false. The caller interprets false as authoritative out-of-band account deletion, removes the only marker, and returns before locking shadow or deleting managed authorized_keys. Once passwd becomes readable, future applies no longer enumerate the live account for revocation.

Refutation attempt: I inspected marker/UID matching, shadow reads, command failure handling, key removal, and #5128 tests. Every later failure correctly retains the marker, but all those guards are unreachable after this ambiguous lookup. Tests cover present, absent, malformed UID/GID, and normal revocation, not passwd read failure.

HPC/invariant check: Identity database loss must be unknown-and-retryable, never proof of absence. No packet-path work is involved.

Why it matters: A transient mount, permission, or I/O error during user removal can leave password and key access active indefinitely while configuration appears applied.

Fix direction: Return found and error separately. Delete provenance only after a successful complete passwd read proves absence; retain and retry on read or matching-record parse errors. Add failure-then-recovery transition tests.

Labels: security, daemon, host-integration, authentication, fail-open

Dedup note: Searched lookupUIDGID, passwd read/unreadable, deprovision marker, account absent, #1916, and #5128. #1916 covers owner/durability mechanics and #5128 establishes revocation, but neither covers read-error/absence conflation at marker deletion.

### C179-096: Day-2 HA changes leave stale strict VIP ownership state

Source IDs: A7-C007

Title: Day-2 HA changes leave stale strict VIP ownership state

Severity: High

Confidence: High

Evidence: pkg/daemon/rg_state.go:82
~~~go
// SetStrictVIPOwnership enables or disables strict VIP ownership mode.
// When enabled, rg_active is derived from VRRP master state only.
func (s *rgStateMachine) SetStrictVIPOwnership(strict bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strictVIPOwnership = strict
}
~~~

Trace: startClusterComms calls syncRGStrictVIPOwnershipMode for the then-current RG list. Ordinary apply updates cluster config but restarts communications only when clusterTransportKey's endpoint fields change; NoRethVRRP, PrivateRGElection, dataplane type, and RG membership are not in that key. A newly added RG therefore keeps strict=false even in native VRRP mode, and mode toggles leave existing machines stale. The setter also changes only the boolean, so an already active state is not reconciled until some later cluster/VRRP event.

Refutation attempt: I enumerated all production calls to syncRGStrictVIPOwnershipMode and SetStrictVIPOwnership, inspected clusterTransportKey, the apply restart gate, and dynamic watchdog reads. Synchronization occurs only under startClusterComms. The state test explicitly triggers SetCluster after changing strict mode because the setter itself does not reconcile. No day-2 caller closes either gap.

HPC/invariant check: Before ownership events are applied, each RG's mode and derived rg_active must match current config. This is control-plane transition work.

Why it matters: Loose state in VRRP mode can create dual ownership, while stale strict state in direct mode can keep a promoted node inactive and blackhole traffic.

Fix direction: Synchronize mode and initialize all current RGs on every relevant commit. Have the setter reconcile and return a transition routed through serialized dataplane application. Test RG addition and both mode directions without transport changes.

Labels: security, availability, daemon, ha, dual-primary, lifecycle

Dedup note: Searched SetStrictVIPOwnership, strict VIP/RG mode, NoRethVRRP, PrivateRGElection, mode reconcile, day-2 VRRP, and RG addition. Corpus matches concern strict validation and direct-mode design, not stale runtime mode or missing day-2 initialization.

### C179-097: RSS idempotence accepts degenerate in-range queue distributions

Source IDs: A7-C008

Title: RSS idempotence accepts degenerate in-range queue distributions

Severity: Medium

Confidence: High

Evidence: pkg/daemon/rss_indirection.go:534
~~~go
	for _, row := range rows {
		for _, q := range row.entries {
			if q < 0 || q >= active {
				return false
			}
		}
	}
	return len(rows) > 0
~~~

Trace: For four workers on six queues, the desired weights are [1,1,1,1,0,0]. A live table containing only queue 0 parses successfully, and every bucket satisfies 0 <= q < 4. indirectionTableMatches returns true, applyRSSIndirectionOne skips ethtool -X, and workers 1 through 3 remain starved on every reconcile.

Refutation attempt: I inspected parseIndirectionTable, indirectionTableIsDefault, callers, and tests. The default-restore helper performs exact round-robin validation, but the workers-less-than-queues path uses only this range test. Existing tests cover valid concentration and out-of-range queues, not missing active queues or skew.

HPC/invariant check: Every nonzero target weight must own buckets, with bounded skew or exact expected layout. This check is host setup, not per-packet work.

Why it matters: A stale/custom table can collapse receive processing to one AF_XDP worker and severely reduce throughput while the daemon reports no change required.

Fix direction: Validate active-queue coverage and distribution, preferably against the deterministic weighted sequence. Add all-zero, missing-queue, and skew tests that require an ethtool repair.

Labels: performance, daemon, rss, af-xdp, host-integration

Dedup note: Searched indirectionTableMatches, RSS queue coverage/distribution, active queue, queue 0, #797, and #805. Existing material covers parser bounds, empty output, worker-count refresh, and default restoration, not range-only acceptance of a one-queue table.

### C179-098: Remote-AS-zero peers leak into address-family and BFD output

Source IDs: A7-C009

Title: Remote-AS-zero peers leak into address-family and BFD output

Severity: Medium

Confidence: High

Evidence: pkg/frr/policy_render.go:754
~~~go
			// this on commit/commit-check; on the tolerant load/peer-sync path
			// it is downgraded to a warning, so this render guard keeps a
			// leniently-loaded remote-as-0 neighbor out of frr.conf entirely
			// rather than bricking the reload for every other peer.
			if n.PeerAS == 0 {
				continue
			}
~~~

Trace: The declaration loop skips PeerAS zero and therefore emits no remote-as statement. Address-family classification later iterates the original bgp.Neighbors slice without that filter and can emit activate, route-map, default-originate, prefix-limit, and next-hop-self lines for the undeclared address. The global BFD accumulator independently includes every BFD-enabled neighbor. Thus tolerant persisted or HA-synced input still contaminates frr.conf despite the comment's whole-peer guarantee.

Refutation attempt: I inspected strict #2963 validation, every BGP neighbor loop, the BFD accumulator, and tests. Local commits reject zero, but tolerant load/peer-sync is explicitly supported by the renderer. The existing guard test gives the peer no family, policy, default, or BFD attributes, so it cannot exercise later loops.

HPC/invariant check: Peer validity must be decided once and reused by declarations, AF policy, and BFD. This is configuration rendering.

Why it matters: One tolerated malformed peer can reject or degrade a managed FRR reload affecting otherwise valid routing peers.

Fix direction: Build one valid-neighbor slice before rendering and use it everywhere. Add IPv4/IPv6 AF, policy/default, and BFD variants to the #2963 regression.

Labels: frr, bgp, configuration-rendering, fail-closed

Dedup note: Searched PeerAS, remote-as zero, AS 0, invalid/undeclared neighbor, AF activate, BFD, and #2963. #2963 covers strict validation and the declaration guard. This residual root is incomplete reuse of that decision in separate AF/BFD loops, with a different fix locus.

### C179-099: An unrenderable static default suppresses the DHCP fallback

Source IDs: A7-C010

Title: An unrenderable static default suppresses the DHCP fallback

Severity: Medium

Confidence: High

Evidence: pkg/frr/config_render.go:225
~~~go
	hasV4Default := false
	for _, sr := range fc.StaticRoutes {
		if sr.Destination == "0.0.0.0/0" {
			hasV4Default = true
			break
		}
	}
~~~

Trace: Deleting the last next hop can leave a non-discard static route object with destination 0.0.0.0/0 and zero NextHops. renderStaticRoute intentionally emits nothing for it. renderDHCPDefaults independently sees only the destination, sets hasV4Default, and skips the lease default, leaving no default route. The IPv6 ::/0 path has the same composition.

Refutation attempt: I inspected discard, ECMP, NextTable, DHCP family selection, and #3872 tests. Explicit discard defaults remain valid suppressors, while zero-next-hop routes are intentionally non-rendering. No shared effective-route predicate or composition test ensures suppression corresponds to an installed route.

HPC/invariant check: A fallback may be suppressed only by a competing route that this apply actually renders in the relevant family/table. This is control-plane rendering.

Why it matters: Removing a static next hop can also remove DHCP WAN or management reachability and cause remote lockout.

Fix direction: Derive suppression from shared static-route renderability/table semantics. Add IPv4 and IPv6 integration tests combining an empty static default with a DHCP default.

Labels: frr, routing, dhcp, availability, configuration-rendering

Dedup note: Searched DHCP default, static default, zero/no next hop, incomplete default, NextTable, and #3872. #3872 owns non-rendering of incomplete routes; it does not cover renderDHCPDefaults suppressing a fallback based on that raw object.

### C179-100: Successfully skipped VPNs retain established IPsec SAs

Source IDs: A7-C011

Title: Successfully skipped VPNs retain established IPsec SAs

Severity: High

Confidence: High

Evidence: pkg/ipsec/manager.go:218
~~~go
// promoteConnNames records newNames as the current applied connection set and
// returns the connections that were present before but are gone now — the
// ones an operator DELETED. The diff keys off the VPN name (map key), not
// renderability, so a VPN that merely became unrenderable (a broken gateway
// reference) is NOT treated as removed and keeps its SAs.
//
// #4898: this is called ONLY after a successful reload, so prevConnNames always
// reflects the last config strongSwan actually loaded — never a config whose
// reload failed. The name/removed diff and the prevConnNames advance stay
~~~

Trace: A valid VPN establishes IKE/child SAs and enters prevConnNames. Tolerant persisted or peer-synced input can then make its gateway, IKE chain, or AH proposal unrenderable. renderConfig omits the connection but returns success, load-all succeeds, and vpnConnNameSet still includes every raw VPN map key. promoteConnNames sees no removal, terminateRemovedConns is not called, and strongSwan's existing child SA continues forwarding despite no loaded renderable connection.

Refutation attempt: I inspected strict validators, all render-skip branches, reload ordering, live-SA enumeration, and explicit deletion teardown. Strict local commit narrows reachability but does not eliminate the renderer's documented HA/recovery callers. #4898 applies only when reload fails; here it succeeds. The skipped map suppresses orphan secrets but is not returned to Manager, and the manager comment explicitly confirms the retained-SA behavior.

HPC/invariant check: After successful apply, every forwarding child SA must correspond to a connection actually rendered and loaded or be actively terminated. This needs no packet-path work.

Why it matters: Malformed or partially synchronized security state can report convergence while a stale peer remains authorized under old selectors and credentials.

Fix direction: Return the exact rendered connection set and promote/diff that set after successful reload. Treat previously applied, now skipped names as removals and terminate their live SAs. Test all skip classes from a valid/up starting state.

Labels: security, ipsec, strongswan, ha, stale-policy, fail-open

Dedup note: Searched unrenderable/skipped VPN, stale SA, vpnConnNameSet, terminate, strongSwan, and prior manager findings. The prior codex-review-175/#4898 root is failed reload advancing state and terminating still-effective SAs; #3941 covers explicit deletion. This is successful reload plus raw-name tracking preventing teardown, a distinct transition and fix.

### C179-101: FRR route-detail failures are reported as successful empty output

Source IDs: A7-C012

Title: FRR route-detail failures are reported as successful empty output

Severity: Low

Confidence: High

Evidence: pkg/frr/status_parse.go:375
~~~go
	for _, cmd := range []string{"show ip route json", "show ipv6 route json"} {
		output, err := m.executor().Vtysh(cmd)
		if err != nil {
			continue
		}
		routes, err := parseRouteJSON(output)
		if err != nil {
			continue
		}
		all = append(all, routes...)
~~~

Trace: GetRouteDetailJSON queries both families, discards each command or JSON error, and always returns nil error. If both fail, CLI and gRPC render an authoritative "No routes"; if one fails, they silently return a partial table. Both callers already branch on non-nil error, but this implementation makes those branches unreachable.

Refutation attempt: I inspected both callers, executor behavior, parseRouteJSON, and status surfaces. There is no family status, warning, log, or secondary query that distinguishes an empty RIB from failed collection.

HPC/invariant check: Empty operational output is authoritative only after required sources execute and parse successfully. This is operator-triggered status work.

Why it matters: FRR outage, timeout, or JSON drift produces false diagnostic evidence precisely during incident response.

Fix direction: Return family-annotated joined errors; if partial results are retained, return them with a non-nil partial error and render incompleteness explicitly. Add one/both-family command and parse failure tests.

Labels: frr, observability, error-propagation, operations

Dedup note: Searched GetRouteDetailJSON, route detail, vtysh/JSON error, status empty, show ip/ipv6 route, and operational failure. No prior root-cause match was found.

### C179-102: Bond partial member failure is recorded as a completed signature

Source IDs: A7-C013

Title: Bond partial member failure is recorded as a completed signature

Severity: High

Confidence: High

Evidence: pkg/routing/bond.go:232
~~~go
		if err := b.ops.LinkSetMaster(memberLink, bondLink); err != nil {
			slog.Warn("failed to enslave member",
				"bond", name, "member", member, "err", err)
			errs = append(errs, fmt.Errorf("bond %s: enslave member %s: %w", name, member, err))
			continue
		}
		b.ops.LinkSetUp(memberLink)
		slog.Info("bond member added", "bond", name, "member", member)
	}
~~~

Trace: createLocked accumulates a LinkSetMaster failure, ignores member LinkSetUp failure, and also skips missing member lookup without recording an error. It nevertheless assigns b.bonds[name] = sig before returning. The first apply can surface some errors, but an identical retry sees the desired signature as already tracked and only brings up the bond device; it never re-enslaves or re-ups missing members. That retry can report success over a partial LAG.

Refutation attempt: I inspected Apply's delete/keep/create passes, #4823 tests, daemon error aggregation, and #5119 no-flap behavior. #4823 proves the initial LinkSetMaster error is returned, but it does not inspect tracking or retry. The no-flap fast path is keyed only by bondSig and has no kernel/member convergence check.

HPC/invariant check: A signature recorded as realized must represent every configured member. Repair is control-plane netlink work and must preserve no-flap behavior for genuinely converged bonds.

Why it matters: Fabric or AE capacity/redundancy can remain degraded while a subsequent commit falsely reports success.

Fix direction: Track per-member realization or leave incomplete signatures retryable, and propagate member lookup/down/up failures. Add failure-then-identical-retry tests without flapping successful members.

Labels: routing, bond, netlink, transactional-apply

Dedup note: Searched bondManager, LinkSetMaster, enslave/member, partial/retry, and #4823. #4823 fixes initial error propagation. This root is state promotion despite that error and the resulting no-retry fast path, which requires different state-machine changes.

### C179-103: Transient link lookup errors discard teardown ownership

Source IDs: A7-C014

Title: Transient link lookup errors discard teardown ownership

Severity: High

Confidence: High

Evidence: pkg/routing/xfrm.go:283
~~~go
func (x *xfrmManager) deleteLocked(name string) error {
	link, err := x.ops.LinkByName(name)
	if err != nil {
		delete(x.xfrmis, name)
		return nil // already gone
	}
	if err := x.ops.LinkDel(link); err != nil {
		// #4901: a failed LinkDel leaves the xfrmi in the kernel. Retain
		// tracking (do NOT delete from x.xfrmis) and surface the error so the
~~~

Trace: Bond and XFRM removal call deleteLocked; any LinkByName error, including EBUSY, timeout, or netlink transport failure, takes the same branch as genuine absence, deletes tracking, and returns nil. Full tunnel Clear likewise skips every lookup error and resets ownership. A later apply has no removed desired entry to drive cleanup. Normal tunnel removal and VRF reconciliation already use isLinkNotFound to distinguish these cases.

Refutation attempt: I inspected isLinkNotFound, normal tunnel removal, bond/XFRM clear/delete, full tunnel Clear, and #4901 tests. #4901 covers LinkDel failure after successful lookup. Its tests do not inject a non-not-found LinkByName error at these branches. Existing sibling code demonstrates that such errors must retain ownership.

HPC/invariant check: Ownership cannot be discarded until absence is proven or deletion succeeds. This is control-plane reconciliation.

Why it matters: VPN, bond, or tunnel removal can silently orphan live kernel devices and stale routing/security state while reporting convergence.

Fix direction: Treat only isLinkNotFound as successful absence; otherwise retain tracking and return a wrapped error. Preserve failed names across full Clear and add transient-lookup retry tests.

Labels: routing, netlink, teardown, transactional-apply, ipsec

Dedup note: Searched xfrmi/bond/tunnel lookup, transient/not-found, teardown ownership, and #4901. #4901 covers failed LinkDel after a successful lookup. This earlier error-as-absence branch has a different root condition and remains untracked.

### C179-104: XFRM reconciliation adopts a same-name non-XFRM link

Source IDs: A7-C015

Title: XFRM reconciliation adopts a same-name non-XFRM link

Severity: Medium

Confidence: High

Evidence: pkg/routing/xfrm.go:167
~~~go
			if link, err := x.ops.LinkByName(ifName); err == nil {
				// Verify the adopted kernel link's ACTUAL if_id matches the
				// desired one before re-tracking it. A kernel xfrmi with the
				// same NAME but a stale Ifid (e.g. a daemon restart after the
				// VPN's derived if_id changed, or a leftover from an aborted
				// recreate) must NOT be silently adopted — Ifid is immutable in
				// place, so a mismatch requires delete+recreate. On match (or a
				// non-xfrmi link of that name, which should not happen) keep the
				// existing adopt behavior.
				if xi, ok := link.(*netlink.Xfrmi); ok && xi.Ifid != ifID {
~~~

Trace: A route-based VPN derives a name and Ifid. When any same-name link exists, the code checks Ifid only if the type assertion to *netlink.Xfrmi succeeds. A dummy, TUN, or other link takes the else branch, is brought up, and is stored in x.xfrmis with the desired Ifid without creating an XFRM interface. Later identical applies retain that false realization.

Refutation attempt: I inspected the stale-Ifid recreate branch, adoption/bring-up failure handling, and reuse tests. Tests seed only matching *netlink.Xfrmi values. No guard handles a failed type assertion; the source comment explicitly preserves that path because it "should not happen."

HPC/invariant check: A route-based VPN is realized only if the kernel link is XFRM type and has the required Ifid. Type validation is cold reconcile work.

Why it matters: A stale or externally created same-name link can make configuration report success while the required IPsec binding is absent, causing silent tunnel outage and false control-plane state.

Fix direction: Reject a non-XFRM collision or delete/recreate it under an explicit managed-namespace policy. Do not track until type and Ifid verify. Add dummy/TUN collision tests.

Labels: routing, ipsec, xfrm, netlink, fail-closed

Dedup note: Searched xfrmi/xfrm wrong type, non-XFRM, adoption, same-name collision, dummy/TUN, and Ifid. Corpus records stale Ifid and bind-interface validation, not adoption of a different kernel link type.

### C179-105: Timed-out metrics scrapes leave the full session collector running

Source IDs: A8-C001

Title: Timed-out metrics scrapes leave the full session collector running

Severity: Medium

Confidence: High

Evidence: `pkg/api/server.go:402-408` sets the promhttp timeout, while `pkg/api/metrics_sessions.go:118-149,177-193` runs one non-context-aware singleflight refresh and always continues both table iterators; `pkg/api/api.go:18-21` exposes no cancellable iterator contract.

```go
	if err := dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			countForward(val.State, val.Flags, &s.ipv4)
		}
		return true
	}); err != nil {
```

Trace: A stale-cache scrape enters `sessionGaugeSF.Do` and the elected leader calls `walkSessionGauges`. Promhttp's timeout can finish the HTTP request while registry gathering continues in its background goroutine. Because neither the collector nor its iterator callback receives or samples a deadline, the leader keeps visiting the remaining v4 and v6 entries after the response has been abandoned. The cache timestamp is updated only after both walks finish, so singleflight coalesces followers but cannot terminate the expensive leader.

Refutation attempt: The three-second TTL, singleflight recheck, ten-second handler timeout, and `MaxRequestsInFlight` were all reopened. They cap refresh frequency and concurrent HTTP work, but none is a lifetime bound inside `walkSessionGauges`. The client_golang v1.23.2 handler implementation explicitly allows gathering to continue after its timeout. I narrowed the original lock claim: the problem is continuing map iteration and its repeated map operations, not one bucket lock held continuously for the entire scan.

HPC/invariant check: An abandoned O(N) management read must stop at a bounded cadence and release shared dataplane resources promptly. The fix can sample a deadline every bounded batch and return `false`; it need not add packet-path work.

Why it matters: A multi-million-entry refresh can continue consuming CPU and dataplane-map access after every requester has already received a timeout, adding pressure exactly when the control plane is overloaded.

Fix direction: Add a collector-owned deadline independent of the HTTP request, extend or wrap the iterator contract so callbacks can abort at bounded intervals, preserve the last good cache on abort, and emit `scrape_ok=0`. Test a blocked/slow iterator through the real promhttp timeout and assert callback activity stops.

Labels: api, metrics, sessions, cancellation, performance, resource-lifecycle

Dedup note: Searched `metrics.*(timeout|scrape|session|walk)`, `promhttp|HandlerFor|singleflight|walkSessionGauges`, `#4162`, `#5233`, and cancellation synonyms throughout `dedup-index.txt`. #4162 introduced TTL/singleflight and HTTP guards; #5233 cancels REST session scans on request context. Neither gives this Prometheus collector a cancellable leader, so this is not a duplicate.

### C179-106: Root provenance sends zeroize through the wrong home and account-deletion path

Source IDs: A8-C002

Title: Root provenance sends zeroize through the wrong home and account-deletion path

Severity: Medium

Confidence: High

Evidence: Source: `pkg/grpcapi/server_diag_zeroize.go:357-369`
```go
		recordedUID, uidErr := readProvisionedMarkerUID(markerFile)
		curUID, curOK := zeroizeLookupUID(name)
		keysFile := filepath.Join(zeroizeHomeBase, name, ".ssh", "authorized_keys")

		removeMarker := true
		switch {
		case !curOK:
			// Account already absent from /etc/passwd — it cannot authenticate.
			// Best-effort clean up any orphaned key residue; nothing to userdel.
			fail(os.Remove(keysFile))
```

Trace: Applying xpf-managed root authentication writes `/root/.ssh/authorized_keys` and a marker named `root` containing UID 0. Zeroize reads a matching current UID, computes `/home/root/.ssh/authorized_keys`, and enters the generic matched-account branch. It therefore misses the real key and invokes `userdel -r root`. On ordinary systems `userdel` refuses the active UID-0 account, the marker is retained, and the RPC returns `Internal`; a tool without that protection would instead be asked to remove the appliance's root identity.

Refutation attempt: I checked the common defensive outcome rather than assuming `userdel` succeeds. That outcome materially reduces expected impact because zeroize fails loudly and preserves the marker; it does not remove the defect, because the real root key remains and every retry follows the same permanently failing path. Normal daemon deprovisioning explicitly treats root separately, confirming generic account deletion is not the intended root lifecycle.

HPC/invariant check: N/A to packet processing. The reset invariant is to revoke each xpf-owned root credential without deleting the mandatory root principal, and to make retries converge.

Why it matters: Appliances that have used managed root authentication cannot complete factory reset through this RPC and retain the old root SSH key until manually repaired. The privileged reset path also issues an intrinsically unsafe root-account deletion command.

Fix direction: Handle `name == "root"` before generic account teardown. Remove the provenance-owned `/root/.ssh/authorized_keys`, use the existing root-specific password-locking contract, never call `userdel` for UID 0, and delete the marker only after both revocations succeed. Cover key-only, password-only, combined, and retry failures.

Labels: bug, authentication, zeroize, factory-reset, root, resource-lifecycle

Dedup note: Searched `zeroize.*root`, `root.*zeroize`, `provisioned-users/root`, `userdel.*root`, `/home/root`, and root credential synonyms. The prior local-zeroize finding concerns omission of the config database; #4598 concerns generic marked-user teardown. Neither covers root marker dispatch or the root home/account invariant.

### C179-107: Indeterminate account provenance is erased and zeroize can succeed incomplete

Source IDs: A8-C003

Title: Indeterminate account provenance is erased and zeroize can succeed incomplete

Severity: High

Confidence: High

Evidence: Source: `pkg/grpcapi/server_diag_zeroize.go:260-268`
```go
	data, err := os.ReadFile(zeroizePasswdPath)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
```

Trace: Trace: A marker identifies an xpf-provisioned live account. If `/etc/passwd` cannot be read, the matching UID is malformed, or the marker cannot be read or parsed, ownership becomes unknown. The lookup turns passwd uncertainty into the same boolean used for proven absence; marker uncertainty enters the adjacent stale-marker branch. Neither branch records an error or disables marker removal. The password account can therefore survive while its only retry provenance is deleted, after which `performZeroizeWipe` can return nil and `SystemAction` reports a completed reset.

Refutation attempt: Avoiding `userdel` under uncertain ownership is correct, so I looked for a surfaced incomplete status or retained marker. Only a directory read error and a later `userdel` failure do that. The uncertain pre-delete branches leave `firstErr` nil and `removeMarker` true. A proven UID mismatch can remain non-destructive, but it does not justify conflating I/O and parse failures with proof that no credential remains. The daemon's normal password reconciliation retains provenance on uncertain shadow state, providing a contrary local invariant.

HPC/invariant check: N/A to packet processing. Security-critical ownership uncertainty must fail closed while preserving durable evidence needed for a safe retry.

Why it matters: A transient filesystem error or corrupt marker can produce a green factory-reset result while an old interactive password account remains usable, and repeated resets cannot rediscover that account after the marker is erased.

Fix direction: Return `(uid, found, err)` from passwd lookup and preserve marker read errors separately. Treat read/parse uncertainty as an incomplete reset, retain the marker, and avoid destructive account changes. Keep proven UID mismatch non-destructive but report it as unresolved unless there is explicit durable stale-marker policy. Add true-absence, unreadable, malformed, mismatch, and retry tests.

Labels: security, authentication, fail-open, zeroize, factory-reset, provenance

Dedup note: A8-b2-F002 and A8-b3-F002 are exact duplicates and are merged here. Corpus searches for `zeroizeLookupUID`, `zeroize.*passwd`, `corrupt.*marker`, `unreadable.*/etc/passwd`, provenance, UID, and account-reset terms found #4598's normal teardown and userdel-retry contract, but no prior finding for erasing pre-userdel uncertainty.

### C179-108: MonitorInterface recursively proxies when neither HA peer is primary

Source IDs: A8-C004

Title: MonitorInterface recursively proxies when neither HA peer is primary

Severity: High

Confidence: High

Evidence: Source: `pkg/grpcapi/server_diag_monitor.go:477-492`
```go
	ctx := stream.Context()

	client := pb.NewBpfrxServiceClient(conn)
	peerStream, err := client.MonitorInterface(ctx, req)
	if err != nil {
		return status.Errorf(codes.Unavailable, "peer monitor failed: %v", err)
	}

	for {
		resp, err := peerStream.Recv()
```

Trace: During election, maintenance, disabled, lost, or both-secondary state, node A sees the reth locally but is not primary and opens the same stream on B. B evaluates the unchanged request, is also non-primary, and opens it back on A. Each nested server stream waits on another peer client stream, so the chain consumes connections, streams, goroutines, and memory until a resource limit or cancellation unwinds it.

Refutation attempt: I checked whether cluster state guarantees exactly one primary, whether physical-member forwarding terminates, whether the fabric listener rejects this stream, and whether metadata stops a second hop. The state model explicitly permits both nodes to be non-primary and missing RGs return false. Physical members can terminate based on device presence, but the reth branch exists on both nodes. The method is fabric-allowlisted, and unlike the chassis-forwarding proxy there is no `xpf-no-peer` marker.

HPC/invariant check: One management stream must consume O(1) server/client resources and peer forwarding must have a strict hop bound. This fix is management-only and need not touch the packet path.

Why it matters: A normal HA transition can turn one authorized monitor request into a cross-node stream storm, degrading the control plane responsible for election and dataplane management.

Fix direction: Stamp authenticated forwarded metadata and prohibit another proxy hop. Prefer forwarding only with explicit evidence that the peer owns the RG; otherwise return `FailedPrecondition` with local/peer state. Test both-secondary, hold, lost, disabled, missing RG, and one-primary cases with a maximum-one-dial assertion.

Labels: availability, grpc, ha, monitor, recursion, resource-exhaustion

Dedup note: Searched `MonitorInterface`, `proxyMonitorInterface`, monitor/peer recursion, bounce, loop, both-secondary, hop-marker, and `xpf-no-peer` terms. #4910 covers active monitor streams blocking graceful shutdown, a different lifetime and fix locus; no prior entry covers cross-peer recursive creation.

### C179-109: Canceling any unary RPC can discard the connection's staged configuration

Source IDs: A8-C005

Title: Canceling any unary RPC can discard the connection's staged configuration

Severity: Medium

Confidence: High

Evidence: `pkg/grpcapi/server.go:335-338,563-578` installs the interceptor for every unary call and treats any request context error as disconnect; `pkg/configstore/store_lock.go:227-242` clears candidate, dirty state, lock ownership, and edit path.

```go
	// If the client's context was cancelled (disconnect, Ctrl-C), release any
	// config lock held by this connection.
	if ctx.Err() != nil {
		sessionID := peerSessionID(ctx)
		if sessionID != "" {
			if s.store.ExitConfigureSession(sessionID) {
```

Trace: `EnterConfigure` keys the candidate holder by the HTTP/2 peer address. Every later unary call on the connection receives its own request-scoped context. If any such call reaches a deadline or is canceled while the transport remains reusable, the interceptor derives the same holder and invokes `ExitConfigureSession`. That method sets `candidate=nil` and clears all transaction state, silently abandoning edits staged by earlier calls. Conversely, an idle transport disappearance has no active unary interceptor in which to observe cancellation.

Refutation attempt: Holder matching prevents one peer address from releasing another holder, but it cannot distinguish an owner request deadline from owner connection teardown. gRPC unary contexts are request-scoped, not a stable connection-lifetime signal, and the exit method does not preserve the candidate. The stale-lease machinery limits abandoned locks but does not restore edits discarded by this interceptor.

HPC/invariant check: N/A to packet processing. A configuration transaction may be destroyed only by explicit exit/rollback or a proven session lease expiry, never by cancellation of an unrelated RPC.

Why it matters: One slow or canceled read/mutation can erase an operator's entire staged firewall change while the client continues using the same connection and believes configure mode is still active.

Fix direction: Remove per-unary cancellation as a disconnect hook. Give configure mode an explicit opaque session/lease token, require and refresh it on mutations, and expire it through bounded lease management; until then use explicit exit plus the existing stale timeout. Add a bufconn regression that cancels one unary RPC and then successfully reads/commits the prior candidate on the same connection.

Labels: grpc, configuration, transaction, cancellation, data-loss, resource-lifecycle

Dedup note: Searched `configLockInterceptor`, `ExitConfigureSession`, candidate/staged config cancellation, disconnect, unary context, and lease terms. The corpus contains earlier holder enforcement and stale-lock fixes, but no finding that the global interceptor mistakes one RPC cancellation for transport teardown and destroys the candidate.

### C179-110: Top-session scans allocate two heap objects for every candidate

Source IDs: A8-C006

Title: Top-session scans allocate two heap objects for every candidate

Severity: Medium

Confidence: High

Evidence: `pkg/grpcapi/server_show_flow.go:205-226,277-356` stores slice-backed `net.IP` values and constructs both before bounded top-K admission.

```go
		srcIP := make(net.IP, len(key.SrcIP))
		copy(srcIP, key.SrcIP[:])
		dstIP := make(net.IP, len(key.DstIP))
		copy(dstIP, key.DstIP[:])
		consider(topCand{
```

Trace: `sessions-top` scans each forward v4 and v6 entry. Before `consider` can reject a below-threshold row, the callback allocates and copies source and destination slices into a `topCand`. Independent `go test -gcflags=-m=2` output at the frozen SHA reports all four v4/v6 `make(net.IP, 4|16)` sites as escaping to the heap. The heap retains at most 20 rows, but allocation count remains approximately twice the number of scanned forward sessions.

Refutation attempt: I inspected whether fixed-size keys remain stack values, whether compiler optimization elides rejected candidates, and whether tests measure allocations. The explicit escape report rules out stack allocation at all four sites. Existing tests verify ranking and bounded AppID enrichment only. O(N log K) comparisons and O(K) retention therefore do not establish bounded allocation behavior.

HPC/invariant check: This is a management scan rather than the Rust packet loop, but a bounded top-K query should have O(K) retained memory and allocation count independent of N. Fixed arrays in `topCand` preserve that invariant without locks or packet-path changes.

Why it matters: On a 10-million-session appliance, one read-only query can create roughly 20 million short-lived objects, causing hundreds of megabytes of allocation churn, long GC work, and control-plane latency.

Fix direction: Store addresses as fixed `[16]byte` fields plus family/length in `topCand`, and convert only the at-most-20 survivors to `net.IP` while formatting. Add an allocation benchmark or `AllocsPerRun` regression that stays flat as the input table grows.

Labels: performance, memory, gc, grpc, sessions, bounded-work

Dedup note: A8-b2-F005 and A8-b3-F004 are exact duplicates and are merged here. Searches for `sessions-top`, `showSessionsTop`, `topCand`, `net.IP.*alloc`, top-K, heap, and session allocation terms found the separate unbounded filtered-clear key snapshot but no prior per-candidate address-allocation finding.

### C179-111: Dynamic-address status exposes credentials embedded in feed URLs

Source IDs: A8-C007

Title: Dynamic-address status exposes credentials embedded in feed URLs

Severity: Medium

Confidence: High

Evidence: Source: `pkg/grpcapi/server_show_security_text.go:860-868`
```go
		for name, feed := range cfg.Security.DynamicAddress.FeedServers {
			fmt.Fprintf(buf, "Feed server: %s\n", name)
			fmt.Fprintf(buf, "  URL: %s\n", feed.URL)
			if feed.FeedName != "" {
				fmt.Fprintf(buf, "  Feed name: %s\n", feed.FeedName)
			}
			if feed.UpdateInterval > 0 {
				fmt.Fprintf(buf, "  Update interval: %ds\n", feed.UpdateInterval)
			}
```

Trace: Trace: The dynamic-address configuration accepts an HTTP request URL, including standard userinfo and query components, and the feed manager uses that URL for the outbound request. A remote CLI `show security dynamic-address` maps to the gRPC `ShowText` topic and calls `showDynamicAddress`, which interpolates the raw string. The output therefore returns embedded basic-auth material or query tokens to a read-only status consumer instead of the redacted form used for logging hygiene.

Refutation attempt: I checked strict endpoint validation and the feed request constructor. They require a usable HTTP(S) endpoint but do not prohibit userinfo or credential-bearing query strings. I also checked whether `FeedServer.URL` is a `Secret` or display rendering passes through `RedactURL`; it is a plain string and this path calls no redactor. Loopback clamping reduces network exposure but does not make secrets appropriate in a view-level response available to local management clients.

HPC/invariant check: N/A to packet processing. Secret-bearing configuration values must cross view/status boundaries only in redacted form.

Why it matters: Read-only operators, local users able to reach the management socket, logs of command output, and automation archives can obtain credentials that authorize the external threat-feed service.

Fix direction: Render `config.RedactURL(feed.URL)` and treat URL userinfo/query components as secret-bearing in all show/export surfaces. Add tests for userinfo, token query, ordinary URL, and malformed-but-stored tolerant-load values.

Labels: security, credential-exposure, grpc, dynamic-address, feeds, redaction

Dedup note: Searched feed URL, userinfo, query-token, credential, `RedactURL`, dynamic-address show, and secret-rendering terms. Existing entries cover malformed feed endpoint validation, oversized invalid samples, and DDNS transport security; none cover this gRPC status renderer disclosing the configured URL.

### C179-112: Structured NAT statistics suppress counter and session-scan failures

Source IDs: A8-C008

Title: Structured NAT statistics suppress counter and session-scan failures

Severity: Medium

Confidence: High

Evidence: Source: `pkg/grpcapi/server_helpers.go:153-163`
```go
	sessions := s.sessionStore()
	_ = sessions.ForEachV4(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		add(val.IsReverse, val.Flags, val.IngressZone, val.EgressZone)
		return true
	})
	_ = sessions.ForEachV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		add(val.IsReverse, val.Flags, val.IngressZone, val.EgressZone)
		return true
	})
	return counts
```

Trace: `GetNATPoolStats` initializes used ports and session counts to zero. A missing/failed `nat_port_counters` map read leaves `used64` unchanged, which is then presented as zero utilization and full availability. Session iteration errors are assigned to `_`; a v4 failure or a v6 failure after partial callbacks is returned as a complete count. `GetNATRuleStats` applies the same zero fallback defensively, although the current userspace rule-counter implementation normally returns nil error. The protobuf carries no unavailable/partial bit.

Refutation attempt: I separated currently reachable errors from merely defensive interface branches. `ReadNATRuleCounter` currently returns an in-memory offset without error, so the rule-counter arm alone would not sustain the finding. `ReadNATPortCounter` does return missing-map/lookup errors, and both session-store iterators propagate backend failures that the gRPC helper drops. Those independent production paths preserve the root cause and impact.

HPC/invariant check: Management telemetry must distinguish authoritative zero from unavailable or partial data. Propagating an error/status adds no packet-path work and avoids retries inside the scan.

Why it matters: Operators can see a failed NAT counter backend as an empty, fully available pool or undercount active translations, leading to incorrect capacity and failover decisions.

Fix direction: Return `Internal` when an all-or-nothing stats RPC cannot read required data, or add explicit per-row/response availability and partial-status fields. Stop iteration on the first error, never publish partial counts as complete, and test missing map plus v4/v6 mid-scan failures.

Labels: grpc, nat, telemetry, observability, fail-open, partial-data

Dedup note: Searched NAT telemetry/counter errors, zero fallback, partial session scans, pool availability, `NATPortCounter`, and `countNATSessions`. Prior NAT entries concern wrong counter joins and counter design; no corpus item covers this structured gRPC error-suppression policy.

### C179-113: Request exec deadlines do not bound buffered response bytes

Source IDs: A8-C009

Title: Request exec deadlines do not bound buffered response bytes

Severity: Medium

Confidence: High

Evidence: `pkg/grpcapi/exec_timeout.go:29-50` wraps `cmd.Output` and `cmd.CombinedOutput`, both of which buffer all output; `pkg/grpcapi/exec_timeout.go:121-135` caps log lines but not bytes, and `pkg/grpcapi/server_show.go:506-532` appends the complete tail output to the response.

```go
func combinedOutputTimeout(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.CombinedOutput()
}
```

Trace: Show and diagnostic handlers invoke commands such as `ps`, `ss`, `journalctl`, and `tail` through helpers that collect the entire stdout/stderr into a byte slice before returning. The context limits wall time and `WaitDelay` limits pipe-drain delay, but a local command can emit a very large amount within 15 seconds. `show log` limits the requested line count to 10,000, yet a line has no length cap. The handler then copies that output into a `strings.Builder` and a protobuf string, multiplying transient memory before any client receive-size rejection.

Refutation attempt: I checked all helper callers and did not treat every command as attacker-controlled. Several use fixed small row counts, which reduces their exposure. `ps`/`ss` cardinality and configured-log line length remain unbounded by these helpers, and the gRPC server config sets only receive size. A deadline is therefore not a byte ceiling, and the source comment at `clampTailLines` itself recognizes that distinction without implementing one.

HPC/invariant check: Request-path subprocess output needs a fixed byte budget before materialization. A capped writer or bounded read remains off the packet path and should terminate the child once the budget is exceeded.

Why it matters: A read-only management request against a high-cardinality host or large-line log can force large allocations and GC pressure, potentially destabilizing the daemon before the response is rejected or delivered.

Fix direction: Replace `Output`/`CombinedOutput` on response paths with bounded stdout/stderr writers, return `ResourceExhausted` on overflow, and cap the final protobuf payload. Preserve useful truncated diagnostics only where the API explicitly marks truncation. Test one fast producer and one 10,000-line file with oversized lines.

Labels: grpc, exec, memory, resource-exhaustion, bounded-output, management

Dedup note: Searched `#1805`, bounded exec, `CombinedOutput`, unbounded output/bytes, response size, tail clamp, and process-output allocation. #1805 added time and wait bounds while explicitly retaining the buffering helpers; no prior entry tracks the independent byte-bound omission.

### C179-114: Malformed routing destinations are reported as valid no-route results

Source IDs: A8-C010

Title: Malformed routing destinations are reported as valid no-route results

Severity: Low

Confidence: High

Evidence: `pkg/grpcapi/server_show_routes_text.go:178-275` validates selector shape and keys, but after a destination parse failure leaves `filterIP` nil and falls through to the ordinary no-match output.

```go
		filterIP, _, filterErr := net.ParseCIDR(filterCIDR)
		if filterErr != nil {
			filterIP = net.ParseIP(dest)
		}
		var best *routing.RouteEntry
```

Trace: A request such as `test-routing:dest=not-an-ip` passes the key/value parser, then fetches the route table. CIDR parsing fails and `net.ParseIP` returns nil. Every route match is guarded by `filterIP != nil`, so no candidate can win. The response prints `Routing lookup for not-an-ip` followed by `No matching route found`, conflating invalid input with an authoritative FIB result.

Refutation attempt: The recent selector hardening correctly rejects malformed segments, empty values, unknown keys, and duplicate grammar in adjacent work, but it does not validate the `dest` value. Neither `ParseCIDR` nor `ParseIP` normalizes a bad value into a usable address, and there is no later error branch. This is diagnostic misclassification rather than route mutation, which keeps severity Low.

HPC/invariant check: N/A to packet processing. Invalid management input must fail before an expensive backend query and must not be rendered as valid operational state.

Why it matters: Operators and automation can diagnose a syntax error as missing routing, wasting incident time and producing false no-route alerts.

Fix direction: Parse and validate `dest` before fetching routes; return `InvalidArgument` or the text surface's explicit invalid-destination diagnostic. Add malformed IPv4, malformed IPv6, valid host, and valid CIDR tests.

Labels: correctness, grpc, routing, input-validation, diagnostics

Dedup note: Searched invalid/malformed routing destination, `test-routing`, `No matching route`, selector validation, and `ParseCIDR` terms. The prior ShowText finding rejects duplicate selector keys; it does not validate the destination value or share this branch's fix.

### C179-115: PD-only DHCPv6 leases serialize an invalid address literal

Source IDs: A8-C011

Title: PD-only DHCPv6 leases serialize an invalid address literal

Severity: Low

Confidence: High

Evidence: `pkg/grpcapi/server_dhcp.go:11-38` unconditionally stringifies every lease address; `pkg/dhcp/dhcp.go:1558-1585` explicitly creates a valid PD-only lease without setting `Address`, and `pkg/dhcp/commit.go:180-201` stores it.

```go
		info := &pb.DHCPLeaseInfo{
			Interface: l.Interface,
			Family:    family,
			Address:   l.Address.String(),
			LeaseTime: l.LeaseTime.String(),
```

Trace: With an IA_PD-only client, `parseV6Reply` accepts a live delegated prefix, leaves `Lease.Address` at the zero `netip.Prefix`, and uses the prefix lifetime for renewal. `commitLease` intentionally stores that lease even though no address is valid. `GetDHCPLeases` serializes `l.Address.String()` without `IsValid`; Go's zero-prefix string is `invalid Prefix`. The later delegated-prefix loop attaches valid PD data to the malformed-address row but never clears its address.

Refutation attempt: I checked whether PD-only replies are rejected, omitted from `Leases`, or represented only by the standalone delegated-prefix branch. They are explicitly supported and stored as a lease, so the first loop creates a matching inet6 row before PD attachment. The bug is confined to structured rendering and does not invalidate the delegated prefix itself, supporting Low severity.

HPC/invariant check: N/A to packet processing. Optional structured fields must be empty when absent rather than contain a library sentinel that looks like malformed data.

Why it matters: API clients that parse every non-empty address as CIDR can reject a valid DHCP response or alert on a fabricated bad lease during normal PD-only operation.

Fix direction: Set `Address` only when `l.Address.IsValid()`, leaving it empty for PD-only rows, or model PD-only bindings explicitly. Add IA_PD-only, IA_NA-only, and combined fixtures.

Labels: correctness, dhcpv6, grpc, structured-api, prefix-delegation

Dedup note: Searched DHCP PD-only, delegated prefix, `invalid Prefix`, lease address, and `GetDHCPLeases` terms. Prior DHCP findings cover empty output on read failure, DUID labeling, and prefix lifetime behavior; none cover this protobuf serialization sentinel.

### C179-116: gRPC zeroize ignores the daemon's active custom config path

Source IDs: A8-C012

Title: gRPC zeroize ignores the daemon's active custom config path

Severity: High

Confidence: High

Evidence: Source: `pkg/grpcapi/server_diag_zeroize.go:416-426`
```go
var performZeroizeWipe = func() error {
	// Config state FIRST — the security-critical erasure. A failure here can
	// leave prior-tenant config/secrets on disk, so it is surfaced to the
	// caller (#4576).
	err := zeroizeConfigDir(defaultConfigDir, defaultConfigBase)

	// Rendered service configs (#4585): also security-critical — routing-auth
```

Trace: Trace: `xpfd -config /srv/xpf/tenant.conf` constructs the authoritative config store beside that file. The zeroize RPC invokes a package-global, zero-argument closure that always erases `/etc/xpf/xpf.conf` and its database artifacts. If the default tree is absent or wipes clean, the custom `.configdb`, journal, rollback/rescue material, and config remain untouched while the other fixed cleanup steps can all succeed. The RPC then states configuration was erased, and restart with the same flag reloads the prior tenant.

Refutation attempt: I followed the flag through daemon construction and the gRPC `Config` literal. The live store is available to the server, but neither its configured source path nor an instance reset function reaches `performZeroizeWipe`. Tests that inject a temporary directory call `zeroizeConfigDir` directly and therefore do not exercise production path selection. The source comment declaring non-default paths out of scope conflicts with a supported daemon flag and the unconditional factory-reset success claim; it is not an external guarantee.

HPC/invariant check: N/A to packet processing. Factory reset must target the exact authoritative store selected by the running process and must fail closed if that identity is unavailable.

Why it matters: A device can report successful zeroize while retaining reloadable policy and secret material such as PSKs, WireGuard keys, SNMP communities, and rollback history, making re-tenancy unsafe.

Fix direction: Make zeroize instance-specific: pass the configured path or, preferably, a daemon/store-owned factory-reset closure into `grpcapi.Config`, derive directory/base from that exact path, and reject unavailable identity rather than falling back. Add an RPC-level custom-path regression.

Labels: security, grpc, zeroize, factory-reset, configuration, secret-retention

Dedup note: Searched zeroize with custom/non-default/config path, `/etc/xpf`, `-config`, `defaultConfigDir`, and factory-reset config terms. #4576/#4858 and the prior local CLI finding concern erasing the default authoritative database; none cover loss of the supported runtime path at this gRPC closure.

### C179-117: GetSessions silently degrades requested cluster views to local-only data

Source IDs: A8-C013

Title: GetSessions silently degrades requested cluster views to local-only data

Severity: Medium

Confidence: High

Evidence: `pkg/grpcapi/server_sessions.go:539-586` returns without response state on peer-not-alive, later page, dial failure, or RPC failure; `proto/xpf/v1/xpf.proto:361-390` gives `GetSessionsResponse` a nullable peer but no peer status/error fields.

```go
	conn, err := s.dialPeer()
	if err != nil {
		slog.Warn("failed to dial peer for sessions", "err", err)
		return
	}
```

```go
	peerResp, err := client.GetSessions(peerCtx, peerReq)
	if err != nil {
		slog.Warn("failed to fetch peer sessions", "err", err)
	} else {
		resp.Peer = peerResp
	}
```

Trace: A caller sets `include_peer=true`. Standalone mode, a dead heartbeat, cursor continuation, dial failure, timeout, or peer RPC error all leave `resp.Peer=nil` while the local `GetSessions` RPC succeeds. The response has no completeness field, so a caller cannot distinguish not applicable, intentionally first-page-only behavior, or an HA partition. Sibling session-summary and zone-pair-summary RPCs already carry `PeerFetchStatus`, but this list schema does not.

Refutation attempt: I checked both legacy and cursor call sites, peer liveness checks, recursion prevention, and generated schema. Logging is not part of the client contract, and `PeerAlive` suppresses the attempt without proving the peer has no relevant state. First-page-only peer paging may be a deliberate protocol compromise, but returning the same nil representation for that choice and a failed peer fetch remains ambiguous. The earlier REST pagination undercount lives in `pkg/api/sessions.go`; it does not add status here.

HPC/invariant check: HA management responses requested as cluster-wide must expose whether they are complete. An additive enum/error field changes no packet-path behavior and avoids implicit retries.

Why it matters: During a peer restart or partition, operators and automation can undercount sessions and miss peer-only NAT/application state while receiving a successful response that appears authoritative.

Fix direction: Add `peer_status` and bounded `peer_error` fields using the existing `PeerFetchStatus` model. Classify standalone/no-request, later-page suppression, dead heartbeat, dial failure, and RPC failure distinctly; document or redesign peer pagination. Add all outcome tests.

Labels: grpc, ha, sessions, observability, partial-data, fail-open

Dedup note: Searched `fetchPeerSessions`, `GetSessions.*peer`, `include_peer`, peer nil/local-only/unreachable/status, and pagination terms. The corpus's REST `include_peer=true` bug is a first-page gating error in `pkg/api/sessions.go`; #5320 covers summary RPC completeness. This surviving gRPC list schema and handler are distinct.

### C179-118: Deferred power-action failures are completely unobservable

Source IDs: A8-C014

Title: Deferred power-action failures are completely unobservable

Severity: Low

Confidence: High

Evidence: `pkg/grpcapi/server_diag_system_action.go:53-86` returns success immediately and discards the delayed command result; `pkg/grpcapi/exec_timeout.go:52-62` shows `runTimeout` supplies a real error that could be handled.

```go
var schedulePowerAction = func(systemctlArg string) {
	go func() {
		time.Sleep(1 * time.Second)
		// context.Background(): a confirmed power action must not be
		// cancelled by client disconnect. Errors ignored as before.
		runTimeout(context.Background(), "systemctl", systemctlArg)
	}()
}
```

Trace: Reboot, halt, and power-off journal the request, schedule a goroutine, and return a definitive transition message. One second later the goroutine runs bounded `systemctl`. A missing executable, D-Bus/systemd rejection, permission error, or timeout is returned by `runTimeout`, but the void scheduler drops it. The machine remains running and neither logs nor an action-status API records failure.

Refutation attempt: An asynchronous power RPC can reasonably acknowledge that work was scheduled before the actual shutdown and cannot guarantee the final hardware state. That refutes treating every later failure as a synchronous RPC correctness error and keeps severity Low. It does not justify discarding the command-submission result without any log or status, especially while the response says the node is going down now and tests assert only callback invocation.

HPC/invariant check: N/A to packet processing. Deferred lifecycle operations need an observable accepted/failed state, and every returned command error must be consumed exactly once.

Why it matters: Maintenance automation can proceed assuming a node is leaving service when it remains active, with no local diagnostic explaining the failed transition.

Fix direction: Prefer a systemd scheduling primitive that returns acceptance before the RPC completes. If execution must stay asynchronous, make the scheduler consume and log errors durably and expose action status; soften the response to an accepted-request message. Add injected failure tests for all three verbs.

Labels: grpc, system-action, observability, error-handling, resource-lifecycle

Dedup note: Searched `schedulePowerAction`, systemctl reboot/halt/poweroff errors, ignored command results, false success, and action status. #1805 bounds command runtime but explicitly preserves ignored power-action errors; no prior corpus entry tracks their total lack of observability.

### C179-119: Concurrent event-action queue rebuild can evict an already-admitted unrelated remediation

Source IDs: A9-C001

Title: Concurrent event-action queue rebuild can evict an already-admitted unrelated remediation

Severity: Medium

Confidence: High

Evidence: `pkg/eventengine/engine.go:625` refills the shared channel non-atomically and explicitly handles a producer winning a newly opened slot.

```go
	for _, item := range all {
		select {
		case e.actions <- item:
			e.counters.queueDepth.Add(1)
			if item.policyName == a.policyName {
				replaced = true
			}
		default:
			// Still no room (lost the race to another producer, or the queue
```

Trace: A full channel sends producer Z into `supersede`. It drains admitted actions to a private slice, opening shared capacity. `HandleEvent` is explicitly callable by concurrent probe goroutines, and no producer lock spans this operation. Another producer can fill an opened slot before Z refills. When refill reaches a displaced unrelated survivor, the nonblocking `default` drops it and only increments the generic queue-full counter; the sole worker can never execute that admitted remediation.

Refutation attempt: The worker is a single consumer, but producers remain concurrent and the source comment explicitly acknowledges losing a refill race. `TestQueue_ConcurrentProbesSerialize` uses only eight actions against a depth-64 queue, while the two supersede tests drive no producer during refill. Race detection cannot expose this legal channel schedule.

HPC/invariant check: This is a bounded control-path queue, not packet-path work. Its invariant is that overload rejects the new arrival or replaces only the same-policy stale entry; it must not evict an unrelated action that admission already accepted.

Why it matters: During a multi-policy failure storm, an older safety remediation can disappear solely because a later producer races queue reconstruction, leaving the intended configuration response unapplied at the worst time.

Fix direction: Serialize producer-side queue mutation with a bounded queue state machine or mutex while retaining a sole worker, and atomically replace only the matching policy. Add a barrier test that pauses after drain, admits another producer, resumes refill, and verifies every unrelated survivor remains exactly once in FIFO order.

Labels: event-options, concurrency, remediation-queue, observability

Dedup note: Corpus searches for `eventengine`, `supersede`, `action queue`, `queue rebuild`, `concurrent`, `drain`, `refill`, and `survivor` found #2869. That issue fixed prepending/LIFO ordering and double-counting in an uncontended rebuild; it did not serialize producers or prevent survivor loss between drain and refill.

### C179-120: Accepted trap-group categories do not filter link notifications

Source IDs: A9-C004

Title: Accepted trap-group categories do not filter link notifications

Severity: Medium

Confidence: High

Evidence: `pkg/config/compiler_system.go:1305` recognizes `categories` only to discard it, leaving no runtime field to enforce.

```go
							// `version v1` group silently emitted v2c traps that a
							// v1-only receiver drops.
							tg.Version = nodeVal(prop)
						case "categories":
							// Accepted trap-group leaf (schema-declared). Not
							// consumed by the link-trap runtime today; recognized
							// here so a valid key does not trip the unknown-key
							// rejection below.
```

Trace: The schema accepts `trap-group <g> categories <category>` and describes it as the categories sent to the group. Compilation enters the shown case but stores nothing; `SNMPTrapGroup` has no category field. `sendLinkTraps` consequently iterates every group without a link-category guard. A group restricted to another category is indistinguishable from an unrestricted group and receives every linkUp/linkDown notification.

Refutation attempt: Empty categories can reasonably mean all, but that does not rescue a non-empty exclusion. The schema, compiled type, reconcile hash, dispatch loop, and trap tests contain no later filter or preserved category value.

HPC/invariant check: Compile categories once into immutable group-local state and use an O(1) membership check; excluded events must not allocate packets or queue jobs.

Why it matters: Operators cannot isolate alarm classes by receiver. Link flaps reach targets that explicitly excluded them, leaking interface state and adding alarm noise during incidents.

Fix direction: Retain and validate categories in `SNMPTrapGroup`, include them in the reconcile hash, define empty as default-all, and gate link packet construction on `link`. Add strict/lenient compile tests and negative config-to-queue tests.

Labels: snmp, traps, configuration, observability, vsrx-parity

Dedup note: Searches for `trap-group categories`, `SNMPTrapGroup categories`, `categories link trap`, and `trap filter` returned no same-root record. #2990 added the schema and unknown-key validation, while #3948 carried `version`; neither preserved or enforced categories.

### C179-121: One slow SNMP trap destination blocks delivery to every healthy receiver

Source IDs: A9-C005

Title: One slow SNMP trap destination blocks delivery to every healthy receiver

Severity: Medium

Confidence: High

Evidence: `pkg/snmp/traps.go:397` shows each dequeued destination executed synchronously by the sole worker before it can take the next job.

```go
			// Re-check stop before delivering: the outer select picks
			// randomly when both cases are ready, so a job dequeued
			// concurrently with Stop must not be sent after Stop.
			select {
			case <-stop:
				return
			default:
			}
			if err := send(job.target, job.pkt); err != nil {
```

Trace: The schema explicitly permits FQDN targets, and `sendTrap` gives resolution/dial two seconds. All targets and groups enqueue into one FIFO channel drained by one worker. A stale FQDN or resolver failure blocks that worker, so healthy jobs behind it cannot progress. Repeated link events fill the shared depth-256 queue; subsequent jobs for healthy receivers are then dropped with the same global pressure.

Refutation attempt: UDP to an unreachable literal normally fails or writes quickly, but supported FQDN resolution supplies the bounded slow path and tests already model a blocked sender. The async test proves the link-monitor producer returns; it never places a healthy destination behind the blocker. Queue bounding controls memory, not destination isolation.

HPC/invariant check: Telemetry backpressure must be destination-local. A cold DNS/dial must not consume service capacity for unrelated sinks, while worker and queue counts remain bounded.

Why it matters: One stale destination can delay or suppress link alarms to every healthy NMS exactly during an interface event storm.

Fix direction: Use bounded per-target queues/workers or a bounded fair worker pool that prevents one target from occupying all service slots. Add a deterministic blocked-target/live-target progression test and saturation coverage.

Labels: snmp, traps, concurrency, backpressure, observability

Dedup note: Searches for `SNMP trap head-of-line`, `slow target`, `healthy target`, `single worker`, `trapWorker`, and `trap queue stall` returned no same-root match. #2991 moved blocking work off the producer but intentionally introduced one serial worker; it did not isolate destinations.

### C179-122: Live SNMP reconfiguration leaves old trap jobs authorized for delivery

Source IDs: A9-C006

Title: Live SNMP reconfiguration leaves old trap jobs authorized for delivery

Severity: Medium

Confidence: High

Evidence: `pkg/snmp/traps.go:272` freezes both the old destination and prebuilt community-bearing packet into an unversioned job.

```go
				a.enqueueTrap(trapJob{
					target:  target,
					pkt:     pkt,
					group:   tg.Name,
					event:   "link" + direction,
					iface:   ifname,
					ifindex: ifindex,
				})
```

Trace: A slow send holds the worker while old jobs accumulate. Enabled-to-enabled daemon reconciliation calls `Agent.UpdateConfig`, which swaps only `cfg` and `v3Users`; it does not stop the agent or touch the trap queue. Queued jobs retain the removed target and old packet bytes, and the worker performs no current-generation check before send. A sender that snapped the old config before the swap can also enqueue stale work afterward.

Refutation attempt: `Stop` now abandons backlog under #4916, but the live reconcile path deliberately avoids `Stop` to preserve UDP/161. No epoch, queue invalidation, destination relookup, or pre-send authorization check covers that path. The already in-flight send may be unavoidable, but the queued backlog is not.

HPC/invariant check: Asynchronous jobs must carry an immutable config generation and be rejected when it is no longer current. The check can be one atomic comparison at enqueue and pre-send.

Why it matters: A commit can report a target removed or credential rotated while old notifications continue to that receiver, extending a stale telemetry and confidentiality window by the queued backlog.

Fix direction: Add a trap-config epoch, stamp jobs, increment it in `UpdateConfig`, and reject stale epochs both after config snapshotting and immediately before send. Add a barrier test that blocks one send, rotates config, releases it, and proves no queued old-target send begins.

Labels: snmp, traps, configuration, concurrency, stale-state

Dedup note: Searches for `trap UpdateConfig`, `reconfig`, `stale queue`, `old target`, `removed receiver`, `rotation`, and `config epoch` found prior codex-review-175/#4916. That root was `Agent.Stop` failing to stop workers and abandon backlog; enabled-to-enabled `UpdateConfig` never executes that fixed path, so the fix locus and triggering lifecycle differ.

### C179-123: Interface collection failures are serialized as a healthy empty SNMP MIB

Source IDs: A9-C007

Title: Interface collection failures are serialized as a healthy empty SNMP MIB

Severity: Medium

Confidence: High

Evidence: `pkg/daemon/daemon_snmp_reconcile.go:146` converts every `LinkList` failure into the same nil slice used for an empty successful result.

```go
func buildSNMPIfData() []snmp.IfData {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	var result []snmp.IfData
```

Trace: A transient or permanent netlink dump error reaches the only production `SetIfDataFn` callback. It returns nil and cannot communicate the error through its `func() []IfData` signature. The per-PDU snapshot caches nil. `ifNumber` encodes `len(nil)` as zero, while table walks return end-of-MIB with no SNMP error, log, or health distinction. Monitoring therefore receives a syntactically successful zero-interface device.

Refutation attempt: The one-dump-per-PDU snapshot correctly bounds cost, but it stores only data. Neither the callback nor `ifSnapshot` carries an error, and the producer does not log or retain last-known-good state. Existing `genErr` support cannot help after this early erasure.

HPC/invariant check: Preserve one bounded netlink collection per relevant PDU, but carry its success bit without retrying or issuing extra dumps.

Why it matters: An agent-side collection fault looks like every interface disappearing, masking the control-plane fault and causing false topology conclusions or missed interface alarms.

Fix direction: Change the callback and snapshot to retain `([]IfData, error)`, then define an explicit SNMP error, health counter, or clearly marked last-known-good policy. Rate-limit logs and test empty-success separately from collection failure.

Labels: snmp, if-mib, netlink, observability, fail-closed

Dedup note: Searches for `SNMP LinkList error`, `ifData failure`, `ifTable empty`, `ifNumber zero`, and `netlink nil` returned no same-root record. #4013 concerns the number of netlink dumps per PDU, not loss of the dump error result.

### C179-124: Hostname-only SNMP EngineIDs collide across identically named appliances

Source IDs: A9-C008

Title: Hostname-only SNMP EngineIDs collide across identically named appliances

Severity: Medium

Confidence: High

Evidence: `pkg/snmp/agent.go:404` supplies only the OS hostname to EngineID construction; no installation identity participates.

```go
func (a *Agent) initEngine() {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	a.engineID = buildEngineID(hostname)
	if len(hostname) > snmpEngineIDMaxLen-(len(engineIDPrefix)+1) {
```

Trace: Two appliances in one administrative domain share a hostname, as can occur with cloned images or pre-provisioned defaults. Both short and hashed-long paths deterministically produce identical EngineID bytes. Managers then cannot key authoritative engine state unambiguously. If the devices also share USM credentials and overlapping boots/time, their localized keys match and a signed request captured for one can pass the other's HMAC and timeliness checks because the transport address is not authenticated.

Refutation attempt: #4917 guarantees the 5..32-octet length and distinguishes different long hostnames; it deliberately preserves identical output for a given hostname. `engineBoots` is state subordinate to EngineID and cannot make two engines distinct. No configured ID, machine-id, MAC, installation UUID, or persisted random identity is mixed in.

HPC/invariant check: Engine identity must be stable across restart and unique in its administrative domain. Generate or configure it once, outside request processing.

Why it matters: Cloned or identically named firewalls can alias in NMS caches and, under common fleet credentials/timing, accept cross-device replayed authenticated requests.

Fix direction: Persist an installation-unique enterprise EngineID with an explicit administrative override, bind engineBoots storage to that identity, and provide a migration path for deployed IDs. Test same-hostname/different-installation uniqueness and restart stability.

Labels: snmpv3, usm, identity, replay, observability

Dedup note: Searches for `EngineID duplicate`, `unique`, `hostname`, `clone`, `collision`, `buildEngineID`, and `#4917` found only prior codex-review-175/#4917's oversized long-hostname defect. That fix bounds and hashes hostname bytes; it does not add a per-appliance uniqueness source.

### C179-125: SNMPv3 USM accepts a mismatched authoritative EngineID

Source IDs: A9-C009

Title: SNMPv3 USM accepts a mismatched authoritative EngineID

Severity: Low

Confidence: High

Evidence: `pkg/snmp/v3.go:208` decodes the authoritative EngineID into `_`, then proceeds using only boots, time, and username.

```go
	// USM fields: engineID, engineBoots, engineTime, userName, authParams, privParams.
	_, usmRest, err := berDecodeOctetString(usmBody) // reqEngineID
	if err != nil {
		slog.Debug("SNMPv3: failed to decode engineID")
		return nil
	}
	reqBoots, usmRest, err := berDecodeInteger(usmRest) // engineBoots
```

Trace: A sender that possesses the local user's localized key builds a packet with another or malformed `msgAuthoritativeEngineID`, but signs the whole packet with that local key. The parser discards the field, selects the local user by name, verifies the valid HMAC, and compares boots/time only against local state. Matching boots/time therefore reaches local MIB dispatch even though the authoritative identity on the wire names a different engine.

Refutation attempt: This is not an unauthenticated bypass: a valid local key is still required, which keeps severity Low. Authentication only proves possession of that key; it does not repair the discarded identity semantic. Existing tests align packet EngineID, localized key, and Agent ID, so they do not exercise a signed mismatch.

HPC/invariant check: Exact bounded byte comparison should occur before HMAC/decryption and MIB work; wrong authoritative engines must fail before dispatch.

Why it matters: The agent accepts semantically misaddressed authenticated traffic and suppresses the expected unknown-engine discovery/error behavior, weakening interoperable engine identity handling.

Fix direction: Retain `reqEngineID`, validate legal length and exact local equality before user dispatch, and return the appropriate report when reportable. Add a signed wrong-ID test using the real local key so HMAC succeeds but identity validation must reject it.

Labels: snmpv3, usm, identity, wire-protocol

Dedup note: Searches for `authoritativeEngineID`, `reqEngineID`, `unknownEngineIDs`, `engineID mismatch`, `discard`, and `validate` found no same-root item. #2611 added a `contextName` empty-view gate and echo; #2649 protects persisted engineBoots; neither validates the incoming USM authoritative EngineID. The raw candidate's separate contextEngineID observation is not needed to retain this narrower root.

### C179-126: Malformed SNMP varbinds are skipped while the remaining PDU executes

Source IDs: A9-C010

Title: Malformed SNMP varbinds are skipped while the remaining PDU executes

Severity: Low

Confidence: High

Evidence: `pkg/snmp/agent.go:1717` advances over a varbind and then silently continues on malformed object-name structure.

```go
		// Decode OID from varbind body.
		if len(vbBody) < 2 {
			continue
		}
		if vbBody[0] != tagObjectIdentifier {
			continue
		}
		oidLen, oidLenBytes, err := berDecodeLength(vbBody[1:])
		if err != nil {
```

Trace: A valid credential sends a BER-valid varbind list containing one malformed varbind sequence followed by a valid one. The outer list and per-varbind lengths parse, so the decoder advances past the malformed element. The shown checks skip it rather than return an error, append the later OID, and return success. GET-family handlers answer fewer bindings than requested; SET reaches authorization/notWritable handling as though the malformed binding never existed.

Refutation attempt: Bounds checks prevent panic and the current MIB has no writable objects, limiting immediate security impact. No later layer compares input cardinality, requires each value TLV, or rejects skipped entries. This is partial protocol execution, not harmless diagnostic tolerance.

HPC/invariant check: Parse each bounded PDU linearly and fail at the first malformed varbind; rejection is cheaper than constructing a partial response.

Why it matters: Managers receive responses that no longer correspond one-to-one with requests, parser differentials are hidden, and any future writable MIB would inherit partial-SET behavior.

Fix direction: Make every malformed varbind fatal; validate one complete OID TLV plus one complete value TLV and no trailing bytes. Add mixed valid/invalid tests for every PDU type and fuzz the full PDU decoder.

Labels: snmp, ber, parser, fail-closed, wire-protocol

Dedup note: Searches for `malformed varbind`, `partial varbind`, `skip`, `ignored`, `decodePDUFields`, and `OID continue` returned no same-root corpus entry.

### C179-127: Unsupported SNMP objects are mislabeled as noSuchInstance

Source IDs: A9-C011

Title: Unsupported SNMP objects are mislabeled as noSuchInstance

Severity: Low

Confidence: High

Evidence: `pkg/snmp/agent.go:884` comments `noSuchObject` but unconditionally emits `tagNoSuchInstance` whenever lookup returns nil.

```go
	snap := a.newIfSnapshot()
	var varbinds []varbind
	for _, oid := range oids {
		val, valTag := a.getOIDValueSnap(oid, snap)
		if val == nil {
			// For v2c GET, return noSuchObject exception.
			varbinds = append(varbinds, varbind{oid: oid, tag: tagNoSuchInstance, value: nil})
		} else {
			varbinds = append(varbinds, varbind{oid: oid, tag: valTag, value: val})
```

Trace: A manager GETs an OID whose object type is not implemented. `getOIDValueSnap` returns nil, the response selects exception tag `0x81`, and the declared `tagNoSuchObject` (`0x80`) is never chosen. The same branch exists in v3. The manager is told a known object lacks that instance rather than that the object itself is unavailable.

Refutation attempt: Missing rows under supported table columns legitimately require `noSuchInstance`; the raw title's word “every” therefore overstated the defect. The lookup API collapses unsupported object and absent instance into the same nil result, and no response-layer classifier can distinguish them, leaving unsupported objects definitely wrong.

HPC/invariant check: This is cold wire classification. A typed lookup result or bounded supported-prefix check is sufficient.

Why it matters: Capability discovery and monitoring can misdiagnose an unsupported MIB object as a transiently absent row or scalar instance.

Fix direction: Return a typed result distinguishing value, `noSuchObject`, and `noSuchInstance`, then test unknown object, malformed/missing scalar instance, absent table row, and valid object for both v2c and v3.

Labels: snmp, mib, wire-protocol, observability

Dedup note: Searches for `noSuchObject`, `noSuchInstance`, `unknown OID`, `tagNoSuchObject`, and SNMP exception classification returned no same-root entry.

### C179-128: SNMPv3 USM reports hard-code security counters to zero

Source IDs: A9-C012

Title: SNMPv3 USM reports hard-code security counters to zero

Severity: Low

Confidence: High

Evidence: `pkg/snmp/v3.go:955` encodes constant `Counter32(0)` for every report built through the shared helper.

```go
func (a *Agent) buildReportPDU(statsOID []int) []byte {
	vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(statsOID))
	vb = append(vb, berEncodeTLV(tagCounter32, berEncodeCounter32(0))...)
	vbList := berEncodeTLV(tagSequence, berEncodeTLV(tagSequence, vb))
	pduBody := berEncodeIntegerTLV(0) // request-id
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	return berEncodeTLV(0xa8, pduBody) // Report PDU tag
```

Trace: Discovery and authenticated stale requests select the correct `usmStatsUnknownEngineIDs` or `usmStatsNotInTimeWindows` OID. No Agent counter is incremented. Discovery encodes zero directly and the timeliness path calls the shown zero-valued helper, so the first and every later report carries Counter32 zero. Tests classify reports by OID and never assert the value.

Refutation attempt: The source calls the value informational, but `usmStats*` objects are counters and the report varbind is their current value. No separate counter owner or later value patch exists. Correct OID selection therefore does not make the emitted telemetry accurate.

HPC/invariant check: Increment relaxed atomics only on cold rejection/discovery paths and preserve Counter32 wrap semantics; no shared request-path lock is needed.

Why it matters: Managers cannot quantify discovery churn, replay/timeliness failures, or clock/boots problems, and the security telemetry is standards-inaccurate.

Fix direction: Add per-Agent atomic counters for implemented USM statistics, increment at the exact event, and encode the resulting value in reports and diagnostics. Test sequential increments, concurrent increments, and wrap behavior.

Labels: snmpv3, usm, counters, security-telemetry, observability

Dedup note: Searches for `usmStats counter`, `zero`, `increment`, `buildReportPDU`, `UnknownEngineIDs`, and `NotInTimeWindows Counter32` returned no same-root entry. #2610 implemented timeliness rejection and #2649 protected boots persistence; neither implemented USM counter state.

### C179-129: BER OID codec corrupts multi-octet first subidentifiers

Source IDs: A9-C013

Title: BER OID codec corrupts multi-octet first subidentifiers

Severity: Low

Confidence: High

Evidence: `pkg/snmp/agent.go:1519` casts the combined first two arcs directly to one byte instead of applying the existing base-128 encoder.

```go
// berEncodeOID encodes an OID value (without tag/length).
func berEncodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}
	// First two components are combined: first*40 + second.
	var encoded []byte
	encoded = append(encoded, byte(oid[0]*40+oid[1]))
	for i := 2; i < len(oid); i++ {
		encoded = append(encoded, berEncodeSubID(oid[i])...)
```

Trace: A valid OID such as `2.100.3` combines its first arcs to 180, which requires two base-128 octets. The encoder truncates 180 to one raw byte. The decoder likewise divides only the first octet by 40 and then treats continuation bytes as later arcs. A standards-valid request is therefore decoded to another OID, and error/response paths can echo the mutated name.

Refutation attempt: All currently served constants are rooted at 1.x, so this does not corrupt the existing built-in MIB and severity remains Low. The decoder still accepts arbitrary manager OIDs, and generic responses echo them. Existing 1.3-only tests cannot cover the valid 2.x form.

HPC/invariant check: OID length is bounded by the 4096-byte message. A checked linear base-128 decode/encode preserves hot-path bounds and needs no allocation beyond the existing output.

Why it matters: Generic walks and capability probes using valid joint-iso OIDs receive silently mutated names, and any future 2.x MIB would be unusable.

Fix direction: Encode the combined first value with `berEncodeSubID`; decode one complete base-128 first value and map it to arcs 0/1/2 with overflow and canonical-form checks. Add round trips for `2.100.3`, large arcs, invalid first arcs, and truncated continuations.

Labels: snmp, ber, oid, wire-protocol, interoperability

Dedup note: Searches for `OID first subidentifier`, `base-128`, `berEncodeOID`, `berDecodeOID`, `first*40`, and `2.x` returned no same-root record. The prior TimeTicks BER defect concerns unsigned integer sign encoding, not OID arc framing.

## Medium-Confidence Findings

### C179-019: XDP metadata typed store lacks an alignment guarantee

Source IDs: A1-C019

Title: XDP metadata typed store lacks an alignment guarantee

Severity: Medium

Confidence: Medium

Evidence: Source: userspace-xdp/src/lib.rs:676
```rust
    let meta_ptr = ctx.metadata() as *mut UserspaceDpMeta;
    if (meta_ptr as usize).saturating_add(mem::size_of::<UserspaceDpMeta>()) > ctx.metadata_end() {
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_META_BOUNDS);
    }

    unsafe {
        *meta_ptr = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: mem::size_of::<UserspaceDpMeta>() as u16,
```

Trace: `bpf_xdp_adjust_meta` shifts `data_meta` relative to a frame base whose alignment is not established by the ABI.  The XDP program casts it to `*mut UserspaceDpMeta` and performs a typed store.  The userspace reader explicitly treats the same metadata as potentially unaligned and uses an unaligned read.

Refutation attempt: Fixed metadata size does not prove base alignment, and bounds checks do not establish alignment.  No ABI assertion or alignment adjustment accompanies the typed store.

HPC/invariant check: Cross-domain packet metadata must be byte-addressable or explicitly aligned; typed Rust dereference/store requires alignment on every supported target.

Why it matters: The XDP program relies on undefined behavior/target-specific code generation at a packet boundary and may fail verifier/runtime expectations on stricter architectures.

Fix direction: Serialize into bytes with unaligned-safe writes, or reserve/validate an alignment-preserving metadata layout and document it as an ABI invariant.

Labels: XDP, Rust-safety, metadata, portability

Dedup note: Searches: `data_meta alignment`, `read_unaligned`, `UserspaceDpMeta`, `BPF metadata`.  Prior unaligned map/metric work is a different memory boundary.

### C179-050: RedactURL exposes path-embedded credentials

Source IDs: A3-C020

Title: RedactURL exposes path-embedded credentials

Severity: Low

Confidence: Medium

Evidence: `pkg/config/secret.go:89`
```go
	// Redact userinfo: locate the authority (between "://" and the next
	// delimiter) and replace any "...@" prefix within it.
	if i := strings.Index(s, "://"); i >= 0 {
		authStart := i + len("://")
		// The authority ends at the first '/', '?' or '#'.
		authEnd := len(s)
		for j := authStart; j < len(s); j++ {
			if c := s[j]; c == '/' || c == '?' || c == '#' {
				authEnd = j
				break
```

Trace: A template or check-IP URL with a bearer token in its path has no userinfo or query to redact. `DDNSProvider.String` and validation/error paths call `RedactURL`, which logs that path unchanged.

Refutation attempt: The sanitizer deliberately documents userinfo and query as its supported credential forms and preserves paths for diagnostics. That makes path token sensitivity contextual, hence Medium confidence, but no downstream scrub protects it.

HPC/invariant check: Redaction is control-plane formatting work.

Why it matters: Providers using a path bearer token can leak it in config display, warning, or error logs.

Fix direction: For credential-capable URL fields, redact path components after authority or adopt an explicit field-aware redaction policy; add path-token cases.

Labels: secrets, DDNS, logging, information-disclosure

Dedup note: Searched `RedactURL|URL.*(path|credential|secret).*(redact|leak)|DDNS.*(path|redact)`. #2781 covers userinfo/query and #4051 raw-AST redaction, not preserved path tokens.

### C179-073: VRRP stop can close advertisement sockets before priority-zero resignation

Source IDs: A5-C012

Title: VRRP stop can close advertisement sockets before priority-zero resignation

Severity: Medium

Confidence: Medium

Evidence: `pkg/vrrp/instance.go:2401`

```go
func (vi *vrrpInstance) stop() {
	close(vi.stopCh)

	// Close sockets to unblock any blocking recvmsg in receiver().
	if vi.conn != nil {
		vi.conn.Close()
	}
	if vi.ipv6Conn != nil {
		vi.ipv6Conn.Close()
	}
```

Trace: A MASTER's `stopCh` arm attempts three priority-zero sends (`pkg/vrrp/instance.go:1089-1098`), but the caller immediately closes both sender sockets before waiting for `stopped`. If the caller wins scheduling, sends fail and the peer waits for master-down timeout rather than receiving resignation.

Refutation attempt: The run-loop can win, so this is a race rather than deterministic behavior. Closing receive descriptors is needed to unblock receivers, but it need not precede the owner run-loop's bounded resignation phase; no ordering test currently gates it.

HPC/invariant check: Teardown path only. Preserve bounded shutdown using a short owner-send phase and a forced-close timeout.

Why it matters: Planned removal/replacement can incur avoidable failover delay and traffic disruption.

Fix direction: Let the run-loop close sender sockets after its resignation burst, or separate receive-unblock and sender ownership. Add a gated write-before-close test plus timeout fallback.

Labels: vrrp, shutdown, resignation, ha

Dedup note: Searched `VRRP.*(resign|priority.?0|stop)|socket.*close.*advert`. `#2625` is manager Stop/Start reuse safety, not on-wire resignation ordering.

## Low-Confidence Findings

No findings survived at this confidence tier.

## Coverage & Verification Summary

- Exact-once source coverage: `2555/2555` across 30 batch manifests; no overlap or omission.
- Batch reports: `30/30` structurally and source-evidence validated; all 139 evidence sets matched the frozen tree.
- Area adjudications: `10/10`; every raw ID received exactly one disposition and every canonical evidence block matched source.
- Cross-area merge: every area canonical received exactly one disposition.
- Coordinator Critical/High verification: `46/46` complete; `46` retained/downgraded and `0` dropped.
- Artifact recovery: a support agent deleted the first `/tmp` campaign tree. Original reviewers re-materialized all 30 reports from retained context, preserving recorded report hashes and corrected versions; the full coverage/evidence pipeline was rerun before adjudication resumed.
- Limitations: this was static/read-only. Reviewer-recorded unit/race/vet checks are retained in batch reports, but this campaign did not run live cluster, packet-generator, failover, or production traffic validation.

## Suggested Issue Split

Create one issue per root cause unless entries explicitly share a transactional invariant. Preserve confidence labels during triage and add `vsrx-parity` where listed.

- `C179-004` [High/High]: Runtime reset strands legacy shared CoS credits for non-exact queues (labels: dataplane, CoS, lifecycle, rate-limiting)
- `C179-005` [High/High]: Reconcile acknowledges worker and helper spawn failure with phantom lifecycle state (labels: control-plane, reconcile, worker-lifecycle, HA)
- `C179-007` [High/High]: Failed in-place rewrite mutates aliased UMEM before fallback reuse (labels: dataplane, Rust-safety, UMEM, flow-cache)
- `C179-008` [High/High]: TCP segmentation promotes bytes beyond the IP-declared datagram into payload (labels: dataplane, TCP, segmentation, packet-integrity)
- `C179-011` [High/High]: Flowless TX traffic bypasses every egress output filter (labels: dataplane, output-filter, fragmentation, policy)
- `C179-012` [High/High]: Lossless HA session retries can stall a packet worker past heartbeat expiry (labels: dataplane, HA, event-stream, liveness)
- `C179-015` [High/High]: Deferred or disarmed changed-plan snapshots become accepted baselines without full forwarding validation (labels: control-plane, snapshot, validation, HA)
- `C179-016` [High/High]: Session-delta polling serializes and fsyncs full state while holding ServerState (labels: control-plane, persistence, locking, performance)
- `C179-027` [High/High]: Non-positive HA roll TTL makes the cross-orchestrator lease immediately reclaimable (labels: ha, upgrade-safety, deploy, cli-validation, fail-open)
- `C179-028` [High/High]: NPTv6 drops rule-set scope, globally applies ingress mappings, and rejects multi-scope hydration (labels: bug, nptv6, zone-scope, security-boundary, config-runtime-drift)
- `C179-029` [High/High]: HA import does not reserve an address-only source-NAT reverse identity (labels: bug, snat, cgnat, ha, failover, allocator, session-integrity)
- `C179-035` [High/High]: A MaxInt singleton member-range wraps its induction variable (labels: config-compiler, integer-overflow, availability)
- `C179-036` [High/High]: Literal DDNS URL userinfo bypasses the plaintext credential gate (labels: ddns, tls, credential-disclosure, fail-closed)
- `C179-039` [High/High]: BGP neighbor policy overrides can alias inherited slice storage (labels: bgp, routing, memory-aliasing, fail-open)
- `C179-040` [High/High]: Static-route reject is accepted then erased (labels: routing, static-route, fail-open, silent-drop)
- `C179-041` [High/High]: Repeated SNMP community blocks can erase a clients allowlist (labels: snmp, access-control, duplicate-block, fail-open)
- `C179-052` [High/High]: Confirm resolution deletes durable recovery intent after a failed replacement write (labels: configstore, durability, commit-confirmed, ha, fail-open)
- `C179-054` [High/High]: JSON null active bodies decode as valid empty configuration (labels: configstore, persistence, json, fail-open, policy)
- `C179-055` [High/High]: Zeroize omits external secret archives and atomic-write crash remnants (labels: configstore, zeroize, secrets, durability, data-remanence)
- `C179-062` [High/High]: Heartbeat anti-replay accepts alternation back to a retired authenticated session (labels: security, ha, heartbeat, replay)
- `C179-063` [High/High]: Missing local interface monitor retains healthy election weight (labels: ha, monitor, fail-open)
- `C179-066` [High/High]: Failed peer failover has no remote transfer-out abort (labels: ha, failover, distributed-transaction)
- `C179-067` [High/High]: Event-stream bulk markers can overtake queued sessions and claim an empty authoritative set (labels: ha, session-sync, bulk, ordering)
- `C179-068` [High/High]: Surviving session-sync daemon does not re-prime a rebooted peer (labels: ha, session-sync, reboot, failover)
- `C179-071` [High/High]: VRRP accepts a failed required IPv6 advertisement socket as ready (labels: vrrp, ipv6, readiness, ha)
- `C179-072` [High/High]: VRRP emits role state without verified VIP ownership (labels: vrrp, vip, ownership, ha)
- `C179-078` [High/High]: Malformed session frames can be cumulatively ACKed away by later telemetry (labels: bug, security, ha, session-sync, fail-closed)
- `C179-079` [High/High]: Shim preflight and verification omit production shared-map ABI contracts (labels: bug, upgrade-safety, abi, pinned-maps, availability)
- `C179-082` [High/High]: Candidate XDP attachments can diverge from the last acknowledged snapshot (labels: transactionality, xdp, control-plane, rollback)
- `C179-083` [High/High]: Mandatory userspace control disable errors are discarded before worker teardown (labels: af-xdp, lifecycle, fail-closed, bpf-map, outage)
- `C179-084` [High/High]: Standalone HA-state cleanup failure has no convergence retry (labels: ha, convergence, retry, fail-closed, control-socket)
- `C179-086` [High/High]: Invalid static-NAT host ports widen into whole-address mappings (labels: security, dataplane, static-nat, fail-open)
- `C179-087` [High/High]: Same-version old helpers silently narrow multi-zone global denies (labels: security, policy, version-skew, fail-open)
- `C179-088` [High/High]: Exact-unit host-inbound overrides merge admissions from a conflicting zone (labels: security, host-inbound, zones, lenient-load, fail-open)
- `C179-090` [High/High]: Tagged RETH services resolve logical-unit suffixes instead of VLAN-ID netdevs (labels: daemon, linux-networking, reth, vlan, ha, ipv6, dhcp)
- `C179-091` [High/High]: Device-map preflight fails open when local NIC inventory is unavailable (labels: daemon, device-map, management, fail-open, availability, ha)
- `C179-095` [High/High]: Passwd read errors permanently abandon removed-user credential revocation (labels: security, daemon, host-integration, authentication, fail-open)
- `C179-096` [High/High]: Day-2 HA changes leave stale strict VIP ownership state (labels: security, availability, daemon, ha, dual-primary, lifecycle)
- `C179-100` [High/High]: Successfully skipped VPNs retain established IPsec SAs (labels: security, ipsec, strongswan, ha, stale-policy, fail-open)
- `C179-102` [High/High]: Bond partial member failure is recorded as a completed signature (labels: routing, bond, netlink, transactional-apply)
- `C179-103` [High/High]: Transient link lookup errors discard teardown ownership (labels: routing, netlink, teardown, transactional-apply, ipsec)
- `C179-107` [High/High]: Indeterminate account provenance is erased and zeroize can succeed incomplete (labels: security, authentication, fail-open, zeroize, factory-reset, provenance)
- `C179-108` [High/High]: MonitorInterface recursively proxies when neither HA peer is primary (labels: availability, grpc, ha, monitor, recursion, resource-exhaustion)
- `C179-116` [High/High]: gRPC zeroize ignores the daemon's active custom config path (labels: security, grpc, zeroize, factory-reset, configuration, secret-retention)
- `C179-001` [Medium/High]: Deferred neighbor retransmit omits output-filter reject and log finalization (labels: dataplane, neighbor, output-filter, observability)
- `C179-002` [Medium/High]: GRE decapsulation treats a non-first inner fragment payload as an L4 header (labels: dataplane, GRE, IPv4, IPv6, fragmentation)
- `C179-009` [Medium/High]: First fragments enter segmentation and L4 recompute paths that require a complete datagram (labels: dataplane, fragmentation, TCP, tunnel)
- `C179-010` [Medium/High]: NAT-reversed ICMP errors bypass forwarded TTL and hop-limit semantics (labels: dataplane, NAT, ICMP, routing)
- `C179-013` [Medium/High]: RT_FLOW decodes IPv4 NAT64 translations using the original IPv6 family (labels: event-stream, NAT64, telemetry, protocol)
- `C179-014` [Medium/High]: Divergent fabric publications overwrite fresh links on every worker poll (labels: dataplane, fabric, snapshot, performance)
- `C179-017` [Medium/High]: Unbounded snapshot rx_queues drives overflow-prone binding-plan construction (labels: control-plane, snapshot, resource-exhaustion, validation)
- `C179-018` [Medium/High]: Malformed non-empty NAT64 sync state silently degrades into ordinary NAT state (labels: HA, NAT64, session-sync, validation)
- `C179-019` [Medium/Medium]: XDP metadata typed store lacks an alignment guarantee (labels: XDP, Rust-safety, metadata, portability)
- `C179-023` [Medium/High]: Top-20 session view retains and sorts every matching session (labels: cli, sessions, resource-exhaustion, performance, bounded-memory)
- `C179-024` [Medium/High]: Brief session rendering buffers both complete scans before pager output (labels: cli, sessions, streaming, backpressure, resource-exhaustion)
- `C179-025` [Medium/High]: Show-log count buffers unbounded child output ahead of the pager (labels: cli, logging, backpressure, resource-exhaustion, permissions)
- `C179-030` [Medium/High]: Address-only source NAT falsely exhausts a multi-address non-persistent pool (labels: bug, snat, cgnat, allocator, false-exhaustion, availability)
- `C179-031` [Medium/High]: NAT64 strict commit validation accepts a prefix grammar the runtime drops (labels: bug, nat64, config-validation, contract-drift, availability)
- `C179-032` [Medium/High]: Disabled AppID tuple fallback performs per-session full application scans (labels: appid, performance, control-plane, observability)
- `C179-037` [Medium/High]: Malformed source-NAT pool ranges become the default PAT range (labels: nat, source-nat, silent-default, fail-open)
- `C179-038` [Medium/High]: Malformed static-NAT mapped ports collapse to whole-address NAT (labels: static-nat, grammar, fail-open)
- `C179-042` [Medium/High]: Hostless RPM HTTP targets commit and are counted as path loss (labels: rpm, validation, false-path-loss)
- `C179-043` [Medium/High]: Parser error accumulation amplifies a bounded input into unbounded diagnostics (labels: parser, availability, control-plane, memory)
- `C179-044` [Medium/High]: Lexer silently discards unmatched bracket syntax (labels: parser, configuration-integrity, fail-closed)
- `C179-045` [Medium/High]: Lenient mixed-case host-inbound tokens lose Junos-host exemptions (labels: host-inbound, HA, ipsec, configuration-compatibility)
- `C179-049` [Medium/High]: Equal SNMP client prefixes can bypass restrict by insertion order (labels: snmp, access-control, fail-open)
- `C179-053` [Medium/High]: The boot-critical committed marker is noncanonical and outside AES-GCM authentication (labels: configstore, cryptography, integrity, bootstrap, fail-open)
- `C179-056` [Medium/High]: Shifted rollback tombstones revive stale valid slots after restart (labels: configstore, rollback, durability, state-identity)
- `C179-057` [Medium/High]: Retired-dataplane migration misses wildcard groups that expand into system (labels: configstore, migration, apply-groups, availability, ha)
- `C179-058` [Medium/High]: Disk loading bypasses configuration byte bounds and retains fifty rollback trees (labels: configstore, memory, availability, bounds, startup)
- `C179-059` [Medium/High]: Auto-archive has unbounded asynchronous snapshot admission (labels: configstore, archive, concurrency, memory, backpressure)
- `C179-064` [Medium/High]: Monitor configuration replacement leaves removed failure weights active (labels: ha, config-reconcile, stale-state)
- `C179-065` [Medium/High]: Manual failover batch reports success after partial supersession (labels: ha, failover, transactionality)
- `C179-069` [Medium/High]: Empty-table fast path can permanently suppress IPv6 GC discovery (labels: conntrack, gc, ipv6, aging)
- `C179-070` [Medium/High]: VRRP reconcile ignores advertise interval and GARP count changes (labels: vrrp, config-reconcile, ha)
- `C179-073` [Medium/Medium]: VRRP stop can close advertisement sockets before priority-zero resignation (labels: vrrp, shutdown, resignation, ha)
- `C179-074` [Medium/High]: Session decoder installs an incomplete core record with zero-valued forwarding fields (labels: ha, session-sync, decoder, validation)
- `C179-075` [Medium/High]: Malformed DHCP full-set frame replaces held peer leases with an empty or prefix set (labels: ha, dhcp, session-sync, decoder)
- `C179-080` [Medium/High]: Clear-all leaves userspace global-counter offsets visible (labels: bug, observability, counters, clear-semantics)
- `C179-085` [Medium/High]: Fabric publication failures are converted to successful refreshes (labels: ha, fabric, error-propagation, convergence)
- `C179-089` [Medium/High]: Zone-counter clear races a status poll that can restore old totals permanently (labels: correctness, observability, concurrency, counters)
- `C179-092` [Medium/High]: Device-map teardown loses networkd reload retry debt (labels: daemon, device-map, networkd, transactional-apply, convergence)
- `C179-093` [Medium/High]: Shutdown leaves aggregator and IPsec rebind retry generations running (labels: daemon, lifecycle, concurrency, shutdown, ipsec, observability)
- `C179-094` [Medium/High]: Empty SSH known-host configuration preserves stale managed trust (labels: daemon, ssh, host-integration, teardown, security)
- `C179-097` [Medium/High]: RSS idempotence accepts degenerate in-range queue distributions (labels: performance, daemon, rss, af-xdp, host-integration)
- `C179-098` [Medium/High]: Remote-AS-zero peers leak into address-family and BFD output (labels: frr, bgp, configuration-rendering, fail-closed)
- `C179-099` [Medium/High]: An unrenderable static default suppresses the DHCP fallback (labels: frr, routing, dhcp, availability, configuration-rendering)
- `C179-104` [Medium/High]: XFRM reconciliation adopts a same-name non-XFRM link (labels: routing, ipsec, xfrm, netlink, fail-closed)
- `C179-105` [Medium/High]: Timed-out metrics scrapes leave the full session collector running (labels: api, metrics, sessions, cancellation, performance, resource-lifecycle)
- `C179-106` [Medium/High]: Root provenance sends zeroize through the wrong home and account-deletion path (labels: bug, authentication, zeroize, factory-reset, root, resource-lifecycle)
- `C179-109` [Medium/High]: Canceling any unary RPC can discard the connection's staged configuration (labels: grpc, configuration, transaction, cancellation, data-loss, resource-lifecycle)
- `C179-110` [Medium/High]: Top-session scans allocate two heap objects for every candidate (labels: performance, memory, gc, grpc, sessions, bounded-work)
- `C179-111` [Medium/High]: Dynamic-address status exposes credentials embedded in feed URLs (labels: security, credential-exposure, grpc, dynamic-address, feeds, redaction)
- `C179-112` [Medium/High]: Structured NAT statistics suppress counter and session-scan failures (labels: grpc, nat, telemetry, observability, fail-open, partial-data)
- `C179-113` [Medium/High]: Request exec deadlines do not bound buffered response bytes (labels: grpc, exec, memory, resource-exhaustion, bounded-output, management)
- `C179-117` [Medium/High]: GetSessions silently degrades requested cluster views to local-only data (labels: grpc, ha, sessions, observability, partial-data, fail-open)
- `C179-119` [Medium/High]: Concurrent event-action queue rebuild can evict an already-admitted unrelated remediation (labels: event-options, concurrency, remediation-queue, observability)
- `C179-120` [Medium/High]: Accepted trap-group categories do not filter link notifications (labels: snmp, traps, configuration, observability, vsrx-parity)
- `C179-121` [Medium/High]: One slow SNMP trap destination blocks delivery to every healthy receiver (labels: snmp, traps, concurrency, backpressure, observability)
- `C179-122` [Medium/High]: Live SNMP reconfiguration leaves old trap jobs authorized for delivery (labels: snmp, traps, configuration, concurrency, stale-state)
- `C179-123` [Medium/High]: Interface collection failures are serialized as a healthy empty SNMP MIB (labels: snmp, if-mib, netlink, observability, fail-closed)
- `C179-124` [Medium/High]: Hostname-only SNMP EngineIDs collide across identically named appliances (labels: snmpv3, usm, identity, replay, observability)
- `C179-003` [Low/High]: Fragmented NDP Neighbor Advertisements are accepted for neighbor learning (labels: dataplane, NDP, IPv6, neighbor-security)
- `C179-006` [Low/High]: Unbound binding status retains stale shared-UMEM and drop counters (labels: status, binding-lifecycle, observability)
- `C179-020` [Low/High]: Authoritative neighbor replacement commits a valid subset of a malformed snapshot (labels: control-plane, neighbor, atomicity, validation)
- `C179-021` [Low/High]: Remote session limit wraps past int32 and silently becomes the default (labels: cli, correctness, input-validation, session-observability)
- `C179-022` [Low/High]: Detailed security statistics suppress a failed buffer-detail RPC (labels: cli, observability, error-handling, correctness)
- `C179-026` [Low/High]: Delimiter-concatenated LLDP identifiers collide in the neighbor map (labels: lldp, observability, identity, input-validation)
- `C179-033` [Low/High]: `test policy` completion lacks scalar value slots (labels: cli, completion, grammar)
- `C179-034` [Low/High]: Completion resolves child keywords before mandatory dynamic values (labels: cli, completion, parser-state)
- `C179-046` [Low/High]: Security log stream schema rejects supported severities (labels: logging, schema, configuration, vsrx-parity)
- `C179-047` [Low/High]: Unknown shared-UMEM modes silently disable the feature (labels: shared-umem, AF_XDP, schema, silent-default)
- `C179-048` [Low/High]: Hierarchical leaves can omit a semicolon before a closing brace (labels: parser, grammar, configuration-integrity)
- `C179-050` [Low/Medium]: RedactURL exposes path-embedded credentials (labels: secrets, DDNS, logging, information-disclosure)
- `C179-051` [Low/High]: Screen status inventory omits alarm-without-drop mode (labels: screen, observability, API, CLI)
- `C179-060` [Low/High]: Archive retention deletes the newest commit after a backward wall-clock step (labels: configstore, archive, time, retention)
- `C179-061` [Low/High]: Journal append follows a path that permission migration rejected as a symlink (labels: configstore, journal, filesystem, symlink)
- `C179-076` [Low/High]: IP-monitor status fabricates monitor sections and hides healthy probes (labels: ha, status, observability)
- `C179-077` [Low/High]: HA status reports outbound bulk count as received bulk count (labels: ha, status, observability)
- `C179-081` [Low/High]: NAT counter collision fallback makes rule IDs encounter-order dependent (labels: bug, observability, nat, deterministic-compilation)
- `C179-101` [Low/High]: FRR route-detail failures are reported as successful empty output (labels: frr, observability, error-propagation, operations)
- `C179-114` [Low/High]: Malformed routing destinations are reported as valid no-route results (labels: correctness, grpc, routing, input-validation, diagnostics)
- `C179-115` [Low/High]: PD-only DHCPv6 leases serialize an invalid address literal (labels: correctness, dhcpv6, grpc, structured-api, prefix-delegation)
- `C179-118` [Low/High]: Deferred power-action failures are completely unobservable (labels: grpc, system-action, observability, error-handling, resource-lifecycle)
- `C179-125` [Low/High]: SNMPv3 USM accepts a mismatched authoritative EngineID (labels: snmpv3, usm, identity, wire-protocol)
- `C179-126` [Low/High]: Malformed SNMP varbinds are skipped while the remaining PDU executes (labels: snmp, ber, parser, fail-closed, wire-protocol)
- `C179-127` [Low/High]: Unsupported SNMP objects are mislabeled as noSuchInstance (labels: snmp, mib, wire-protocol, observability)
- `C179-128` [Low/High]: SNMPv3 USM reports hard-code security counters to zero (labels: snmpv3, usm, counters, security-telemetry, observability)
- `C179-129` [Low/High]: BER OID codec corrupts multi-octet first subidentifiers (labels: snmp, ber, oid, wire-protocol, interoperability)
