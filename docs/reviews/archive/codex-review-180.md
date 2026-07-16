# Codex Audit 180: Full-Tree Firewall and Zone-Policy Review

## Executive Summary

Base commit reviewed: `4567ffb78e0bdc0360fecf747f947df5c62ec274`.

Output path: `/tmp/codex-review-180.md`.

This authorized defensive audit reviewed every tracked Go, Rust, C-family, and Python source file at the immutable base, then exercised seven explicit cross-layer lanes around zone/global policy compilation, host-inbound behavior, packet-path ordering, HA authorization, API/simulator parity, and the retired-eBPF compatibility boundary. No repository source was changed.

The final canonical set contains **26** non-duplicate findings: 0 Critical, 3 High, 18 Medium, and 5 Low. Confidence is 24 High, 2 Medium, and 0 Low.

## Duplicate Suppression

The frozen duplicate corpus contains 121 prior final reports and 22,559 indexed titles/root-cause entries, augmented by repository issue and PR history Markdown at the base commit. The source sweep produced 35 raw candidates: 21 survived area adjudication, 13 matched prior roots, and one was dropped after its alleged producer path proved unreachable. Cross-adjudication then considered every retained source root and every lane candidate exactly once.

Cross-adjudication decisions: 26 retain, 17 merge into another campaign root, 15 prior-root duplicate, and 2 drop.

A lane observation was merged when it was independent corroboration of the same runtime mechanism; it was not counted as another issue. A deeper restatement was retained only when it changed the root cause, affected surface, or repair boundary.

## Coverage Checklist

| Area | Expertise scope | Files | Batches |
|---|---|---:|---:|
| A1 | Rust dataplane packet path and memory safety | 420 | 4 |
| A2 | Rust NAT/NAT64/translation | 16 | 1 |
| A3 | Go config compiler, schema, and CLI grammar | 519 | 6 |
| A4 | Configstore, persistence, and crypto-at-rest | 69 | 1 |
| A5 | HA, VRRP, RA, and conntrack sync | 106 | 1 |
| A6 | Go dataplane manager and control publication | 292 | 3 |
| A7 | Daemon lifecycle and host integration | 288 | 3 |
| A8 | gRPC, REST, and management APIs | 303 | 4 |
| A9 | Observability and telemetry | 136 | 2 |
| A10 | Services, CLI/show, and build/deploy tooling | 530 | 5 |
| **Total** | **Tracked source partition** | **2679** | **30** |

The non-source partition contained 2,438 tracked files. Seven lanes reviewed 334 files with executable policy, operational, fixture, or design-contract relevance. The remaining 2,104 were classified with explicit reasons: 908 data/generated fixtures without executable policy semantics, 857 general documentation outside the zone-policy contract, 329 operational inputs whose implementation remained source-owned, nine dependency/build metadata files, and one binary/visual asset.

## Module-by-Module Inspection Log

## A1-b1


| Path | Subsystem and dimensions inspected | Result |
|---|---|---|
| `userspace-dp/benches/prefix_set_lookup.rs` | Policy-prefix benchmark; v4/v6 setup, workload realism, allocation boundary | Negative: benchmark-only; no enforcement or correctness defect. |
| `userspace-dp/benches/session_table.rs` | Session benchmark; forward/reverse/NAT keys, lifecycle and scale | Negative: setup preserves key direction and does not define production authorization. |
| `userspace-dp/benches/snat_allocator.rs` | NAT allocator benchmark; exhaustion, deterministic/random modes, integer bounds | Negative: benchmark coverage is broad; no production path change. |
| `userspace-dp/benches/tx_kick_latency.rs` | AF_XDP kick benchmark; syscall timing and FD lifetime | Negative: bounded harness; no packet-policy semantics. |
| `userspace-dp/build.rs` | Native bridge build/link contract | Negative: rerun/link directives are minimal and coherent. |
| `userspace-dp/csrc/xsk_bridge.c` | XSK FFI; ring ownership, pointer lifetime, errno and wakeup behavior | Negative: wrappers preserve libxdp ownership and return errors; no unchecked length crossing found. |
| `userspace-dp/src/afxdp/bind.rs` | Bind/retry, fill priming, zero-copy requirement, UMEM recovery | Negative: partial fill suffix is retained; total failure is fatal; no frame leak found. |
| `userspace-dp/src/afxdp/bpf_map/ha.rs` | XSK/heartbeat BPF gates and monotonic liveness | Negative: map failures surface; monotonic freshness and stale threshold are consistent. |
| `userspace-dp/src/afxdp/bpf_map/metrics.rs` | BPF diagnostics; mmap offsets, map iteration, unaligned decode | Negative: unaligned key decode is fixed and debug scans are bounded. |
| `userspace-dp/src/afxdp/bpf_map/mod.rs` | Session steering keys, kernel-local action, conntrack mirror ABI | Negative: forward/reverse aliases and delete symmetry checked; failures are surfaced/counted. |
| `userspace-dp/src/afxdp/bpf_map/pin.rs` | Pinned FD RAII and per-CPU degraded counters | Negative: per-CPU buffer sizing and FD close are sound. |
| `userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs` | v4/v6 conntrack publication, NAT reverse key, zone/policy/app attribution | Negative: wire fields and ALG disable directionality match callers. |
| `userspace-dp/src/afxdp/bpf_map_tests.rs` | BPF map ABI and alias tests | Negative: v4/v6/NAT publication contracts represented. |
| `userspace-dp/src/afxdp/checksum.rs` | Scalar/AVX checksum arithmetic, odd lengths, zero checksum rules | Negative: bounds and folding are consistent; no unsafe overread found. |
| `userspace-dp/src/afxdp/cold_path_hist.rs` | Policy-zone-pair histogram; slot aliasing, seqlock and TSC conversion | Negative: work is sampled/bounded and publication uses generation checks. |
| `userspace-dp/src/afxdp/cold_path_hist_tests.rs` | Histogram collision/wrap/snapshot tests | Negative: positive and alias/error cases are covered. |
| `userspace-dp/src/afxdp/coordinator/bpf_maps.rs` | Coordinator map holder | Negative: ownership-only module; no hidden lifecycle. |
| `userspace-dp/src/afxdp/coordinator/cos_leases.rs` | CoS shared lease maps; worker ownership, bounded queue maps | Negative: config-cold allocation and Arc publication only. |
| `userspace-dp/src/afxdp/coordinator/cos_state.rs` | CoS coordinator state | Negative: small ownership bundle; no enforcement logic. |
| `userspace-dp/src/afxdp/coordinator/ha_state.rs` | Shared HA runtime/fabric state | Negative: ArcSwap ownership and defaults are conservative. |
| `userspace-dp/src/afxdp/coordinator/inject.rs` | RPC packet injection; disposition and cold counters | Negative: injection does not silently claim hot-path zone authorization. |
| `userspace-dp/src/afxdp/coordinator/mod.rs` | Coordinator lifecycle, shared maps, snapshot and session ownership | Negative in batch ownership; split validation/forwarding publication observation is a prior-owned dedup handoff below. |
| `userspace-dp/src/afxdp/coordinator/neighbor_manager.rs` | Neighbor warm queue; generation collapse, cap, RG ownership | Negative: bounded queue and generation checks prevent stale warm work. |
| `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` | Bringup order; mandatory maps, replay, worker spawn and resolver | Negative: worker spawn failure tears down; synced replay errors are observable. |
| `userspace-dp/src/afxdp/coordinator/reconcile/mod.rs` | Reconcile preflight/teardown sequencing | Negative: fallible forwarding build precedes publication. |
| `userspace-dp/src/afxdp/coordinator/reconcile/reset.rs` | Reset of coordinator-owned runtime | Negative: state reset is explicit; no stale authorization cache retained. |
| `userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs` | Full snapshot build, validation, publication and preserved sessions | Negative in this batch; Z3/Z5 ordering contracts handed off below. |
| `userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs` | Worker/map/socket teardown | Negative: owned resources are stopped and dropped in order. |
| `userspace-dp/src/afxdp/coordinator/refresh_bindings.rs` | Status projection; readiness, counters, stale slot zeroing | Negative: screen/policy/generated-reply counters and monotonic readiness are copied/zeroed consistently. |
| `userspace-dp/src/afxdp/coordinator/session_manager.rs` | Shared session map holder | Negative: ownership-only structure. |
| `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs` | Same-plan preflight, zone map, atomicity, purge-before-swap | Negative after dedup: build-before-mutate fix is present; two-Arc publication is already prior-owned. |
| `userspace-dp/src/afxdp/coordinator/status.rs` | Process status, HA/session/map/error counters | Negative: publish errors and generated-error suppression are surfaced. |
| `userspace-dp/src/afxdp/coordinator/status_tests.rs` | Status aggregation tests | Negative: representative counter and readiness projections covered. |
| `userspace-dp/src/afxdp/coordinator/supervisor.rs` | Worker panic supervision and stop signaling | Negative: panic is detected and state is made unready. |
| `userspace-dp/src/afxdp/coordinator/tests.rs` | Reconcile/snapshot/HA/worker integration tests | Negative: extensive failure preservation tests; missing consume-after-build test supports A1-b1-F001. |
| `userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs` | WG/GRE thread rotation and endpoint identity | Negative: stale endpoints stop; attachment checks prevent stale encap. |
| `userspace-dp/src/afxdp/coordinator/wg_control.rs` | WireGuard UDP control loop, timers, parsing and thread state | Negative for batch focus; crypto/session design belongs its owning lane. |
| `userspace-dp/src/afxdp/coordinator/wg_control_tests.rs` | WG control transitions and malformed input tests | Negative: bounded receive/control behavior represented. |
| `userspace-dp/src/afxdp/coordinator/worker_manager.rs` | Worker join/stop orchestration | Negative: join ownership and stop paths are explicit. |
| `userspace-dp/src/afxdp/disposition.rs` | Terminal disposition, policy/screen/route counters, zone traffic | Negative: PolicyDenied remains terminal and per-zone traffic is forward-only. |
| `userspace-dp/src/afxdp/ethernet.rs` | EtherType/VLAN constants | Negative: constants agree with parsers. |
| `userspace-dp/src/afxdp/event_emit.rs` | RT_FLOW/screen event encoding, zone/app/action attribution | Negative: casts clamp and deny/reject truth is caller supplied. |
| `userspace-dp/src/afxdp/event_emit_tests.rs` | Event schema and action tests | Negative: v4/v6 and deny/reject fields covered. |
| `userspace-dp/src/afxdp/flow_cache.rs` | Cache key, logical ingress checks, config/FIB/RG stamps, filter replay | Negative: config/FIB/RG/lease and neighbor epochs invalidate; DSCP/per-packet L4 filters decline caching. |
| `userspace-dp/src/afxdp/flow_cache_tests.rs` | Cache authorization/rewrite/invalidation regression suite | Negative: generation, VLAN identity, NAT, filters, BA reclassification and HA epochs covered. |
| `userspace-dp/src/afxdp/forward_request.rs` | Transit terminal/output-filter path, fragment tuple suppression, generated reject | Negative after dedup: output-log physical-zone attribution collides with prior `codex-review-178`; forwarding verdict remains correct. |
| `userspace-dp/src/afxdp/gre.rs` | Native GRE parse/decap/encap, keys, MTU and checksums | Negative: bounded parse and endpoint/ifindex checks prevent stale tunnel use. |
| `userspace-dp/src/afxdp/ha.rs` | HA update, prewarm, synced upsert/delete, bulk export and waits | Negative locally; first-packet-to-failover lifecycle handed to Z5 below. |
| `userspace-dp/src/afxdp/ha_tests.rs` | HA session/NAT/alias and export tests | Negative: stale generation and forward/reverse behavior represented. |
| `userspace-dp/src/afxdp/icmp.rs` | ICMP suppression, TTL expiry, reflected L2/VLAN, output classification | Finding A1-b1-F001: Time Exceeded token is consumed before build feasibility. |
| `userspace-dp/src/afxdp/icmp_ptb.rs` | PMTU decision/builders, declared lengths and RFC suppression | Finding A1-b1-F001 call-site contract: builders can return `None` after the token is consumed. |
| `userspace-dp/src/afxdp/icmp_ptb_tests.rs` | v4/v6 PTB lengths, suppression, VLAN and MTU tests | Negative coverage result: builder failures tested, but no bucket-preservation assertion. |
| `userspace-dp/src/afxdp/icmp_ratelimit.rs` | GCRA buckets, concurrency, reason/zone scope and counters | Finding A1-b1-F001: TE/PTB buckets are process-global and token consumption is irreversible. |
| `userspace-dp/src/afxdp/icmp_ratelimit_tests.rs` | Burst/refill/concurrency tests | Negative mechanics; no test couples failed build to unchanged token state. |
| `userspace-dp/src/afxdp/icmp_tests.rs` | ICMP builders/suppression/checksum tests | Negative builder correctness; missing cross-interface starvation test supports F001. |
| `userspace-dp/src/afxdp/mod.rs` | AF_XDP facade/imports/constants and runtime wiring | Negative: module wiring preserves screen-before-cache and generated-reply helpers. |
| `userspace-dp/src/afxdp/mpsc_inbox.rs` | Bounded MPSC queue memory ordering and ownership | Negative: single-consumer invariant and capacity bounds hold. |
| `userspace-dp/src/afxdp/mpsc_inbox_tests.rs` | Queue wrap/full/concurrency tests | Negative: full and ordering behavior covered. |
| `userspace-dp/src/afxdp/neg_neigh.rs` | Negative neighbor cache TTL/cap | Negative: bounded and expiry-aware; no stale authorization. |
| `userspace-dp/src/afxdp/neighbor.rs` | Neighbor lookup/learning/warm probes and kernel updates | Negative: logical VLAN keys and own-IP/unicast guards hold; syscall cost is prior-owned. |
| `userspace-dp/src/afxdp/neighbor_dispatch.rs` | Missing-neighbor queue/reinject and generated ARP/NDP | Negative: flow keys/fragments are preserved safely; policy decision is carried from caller. |
| `userspace-dp/src/afxdp/neighbor_latency.rs` | Neighbor latency histogram | Negative: saturating/bounded telemetry. |
| `userspace-dp/src/afxdp/neighbor_resolver.rs` | Resolver queue, timeout, generation and reinject | Negative: queue and retries bounded; stale generations collapse. |
| `userspace-dp/src/afxdp/neighbor_resolver_tests.rs` | Resolver timeout/generation tests | Negative: stale work and timeout paths covered. |
| `userspace-dp/src/afxdp/parser.rs` | ARP/NDP/VLAN/ext-header parsing, declared length and checksum | Negative: malformed ARP/NDP fails closed and reads stay declared-length bounded. |
| `userspace-dp/src/afxdp/parser_tests.rs` | Parser malformed/VLAN/ext-header/checksum tests | Negative: positive/negative parser agreement is broad. |
| `userspace-dp/src/afxdp/poll_stages.rs` | Pipeline order: logical zone, screens, fragments, fabric and IPsec host inbound | Negative: screens precede cache/session and use logical VLAN zone; flowless screens fail closed. |
| `userspace-dp/src/afxdp/poll_stages_tests.rs` | Screen/fabric/IPsec/flowless stage tests | Negative: zone and malformed screen paths have RED-on-revert coverage. |
| `userspace-dp/src/afxdp/rst.rs` | TCP reject RST facade | Negative: shared builder only. |
| `userspace-dp/src/afxdp/session_delta.rs` | Open/close replication, event loss latch, BPF/shared cleanup | Negative: correctness-critical queue failure latches out-of-sync; close cleanup is symmetric. |
| `userspace-dp/src/afxdp/sharded_neighbor.rs` | Sharded neighbor concurrency and MAC epoch | Negative: locks are shard-local; MAC-change epoch drives cache invalidation. |
| `userspace-dp/src/afxdp/sharded_neighbor_tests.rs` | Shard and epoch tests | Negative: same-MAC versus changed-MAC behavior covered. |
| `userspace-dp/src/afxdp/shared_ops.rs` | Session prewarm/promotion, poison recovery, aliases and NAT reverse keys | Negative: poisoned maps recover data; failures count rather than masquerade as empty. |
| `userspace-dp/src/afxdp/shared_umem.rs` | Shared UMEM ownership, slot validation, recycle routing | Negative: owner/slot checks and fallible allocation prevent double ownership. |
| `userspace-dp/src/afxdp/shared_umem_tests.rs` | Shared UMEM layout/ownership tests | Negative: invalid slots and partitioning covered. |
| `userspace-dp/src/afxdp/test_fixtures.rs` | AF_XDP fixture snapshots and packet builders | Negative: test-only; zone/policy defaults are explicit. |
| `userspace-dp/src/afxdp/tests.rs` | End-to-end AF_XDP policy/NAT/filter/fragment/cache tests | Negative: strict zone/global/default/Junos-host, fragment, NAT and filter paths are extensive; no new root beyond F001. |
| `userspace-dp/src/afxdp/tunnel.rs` | Local tunnel ingress, endpoint attachment and policy handoff | Negative: endpoint rotation and attachment identity fail closed. |
| `userspace-dp/src/afxdp/tunnel_tests.rs` | Tunnel ingress/rotation/MTU tests | Negative: stale attachment and malformed frame cases covered. |
| `userspace-dp/src/afxdp/worker_queue.rs` | Coordinator-to-worker bounded command queue and poison recovery | Negative: lock poison recovery and cap semantics are explicit. |
| `userspace-dp/src/afxdp/worker_queue_tests.rs` | Command queue full/poison tests | Negative: bounded and recovery behavior covered. |
| `userspace-dp/src/afxdp/worker_runtime.rs` | Worker runtime seqlock/counters and state timing | Negative: owner writes and snapshot reads are coherent. |
| `userspace-dp/src/afxdp/worker_runtime_tests.rs` | Runtime seqlock/state tests | Negative: snapshot and wrap behavior covered. |
| `userspace-dp/src/afxdp/zone_counters.rs` | Zone traffic hot slots, overflow status, stable-ID folding | Negative: overflow is explicit and affects observability only; authorization never consults counters. |

### Contract handoffs

- **Z3 transit dataplane order:** Screens run before IPsec, flow-cache, session lookup, NAT/policy, and forwarding in `poll_descriptor`; output filters run on the post-NAT wire tuple. Terminal/slow/generated exits inspected were screen recycle, SYN-cookie reply, IPsec host pass/deny, cache drop/reject, PolicyDenied, LocalDelivery, MissingNeighbor, NoRoute, NextTable, PTB/Time Exceeded, and filter reject. A1-b1-F001 is a generated-reply resource-order handoff: consume currently precedes build success. Tuple transformations handed off are pre-NAT session key -> DNAT policy tuple -> post-NAT egress wire key, plus NAT reverse canonical/wire companions.
- **Z5 sessions and HA:** First packet evaluates screens/input filter, resolves logical ingress zone and policy/application, installs forward/reverse session metadata, publishes shim/BPF aliases, and may seed a config/FIB/RG/lease-stamped flow-cache entry. HA open/close deltas carry zones, policy/log metadata and NAT; promotion prewarms worker and BPF aliases; RG epoch/lease invalidates cached reuse. BPF publish failures are counted but can cause failover false-deny until repair. No new Z5-owned root is duplicated here.
- **Dedup-only observations:** separate `shared_validation` then `ha.forwarding` publication/consumption can expose mixed generations, but snapshot-generation ordering is already recorded in prior findings and `fable-review-161`; the VLAN output-filter log's physical ingress-zone lookup collides with prior `codex-review-178` (“Logical zone interface references are treated as physical map keys…”). Neither is re-filed.


## A1-b2


### CoS admission, construction, fairness, and marking

- `userspace-dp/src/afxdp/cos/admission.rs` — CoS admission; checked byte/share caps, ECN thresholds, shared-exact accounting, overflow and allocation behavior; no unreported correctness or fail-open issue found.
- `userspace-dp/src/afxdp/cos/admission_tests.rs` — CoS admission tests; checked positive/negative cap, fairness, ECN, and malformed-state coverage; substantive coverage exists, with no separate gap promoted.
- `userspace-dp/src/afxdp/cos/builders.rs` — CoS runtime construction; checked queue/state pairing, bounded allocation, scheduler defaults, exact/shared invariants; no unreported defect found.
- `userspace-dp/src/afxdp/cos/builders_tests.rs` — builder tests; checked invalid and boundary configuration coverage; no separate gap found.
- `userspace-dp/src/afxdp/cos/cross_binding.rs` — cross-binding handoff; checked owner routing, mutex fallback, queue ownership, prepared-frame recycle, and bounded hot-path behavior; no leak or misroute found.
- `userspace-dp/src/afxdp/cos/cross_binding_tests.rs` — cross-binding tests; checked all three fallback stages and ownership failure cases; no separate gap found.
- `userspace-dp/src/afxdp/cos/ecn.rs` — ECN mutation; checked VLAN offsets, IPv4/IPv6 declared header access, checksum adjustment, unsafe UMEM slice lifetime; bounds fail closed and no ownership defect found.
- `userspace-dp/src/afxdp/cos/ecn_tests.rs` — ECN tests; checked truncated, VLAN/QinQ, ECT/non-ECT and checksum cases; no separate gap found.
- `userspace-dp/src/afxdp/cos/fairness.rs` — flow fairness; checked EWMA arithmetic, wrap/saturation semantics and bucket lifecycle; no actionable defect found.
- `userspace-dp/src/afxdp/cos/flow_hash.rs` — flow hashing; checked seeded hashing, keyless lane, bucket bounds and structural expects; no attacker-controlled panic path found under builder invariants.
- `userspace-dp/src/afxdp/cos/flow_hash_tests.rs` — hash tests; checked stability, directionality, keyless and distribution cases; no separate gap found.
- `userspace-dp/src/afxdp/cos/mod.rs` — CoS module surface; checked visibility and module ownership boundaries; no issue found.

### CoS queue operations and V-min

- `userspace-dp/src/afxdp/cos/queue_ops/accounting.rs` — queue accounting; checked enqueue/dequeue byte and active-bucket symmetry, saturation and lease mirrors; no reachable drift found.
- `userspace-dp/src/afxdp/cos/queue_ops/active_buckets.rs` — active bucket lifecycle; checked activation/deactivation idempotence and underflow guards; no issue found.
- `userspace-dp/src/afxdp/cos/queue_ops/drain.rs` — queue drain helpers; checked scratch ownership and rollback boundaries; no loss or double-recycle found.
- `userspace-dp/src/afxdp/cos/queue_ops/fused_diff_tests.rs` — fused selector differential tests; checked cap/no-cap equivalence and randomized state comparison; strong negative coverage, no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/mod.rs` — queue selectors/state; checked min-finish selection, sentinels, promotion/demotion, hard-cap constants and panic invariants; no unreported issue found.
- `userspace-dp/src/afxdp/cos/queue_ops/pop.rs` — pop operations; checked snapshot stack, vtime updates, flow-bucket accounting and local-item ownership; no asymmetry found.
- `userspace-dp/src/afxdp/cos/queue_ops/pop_tests/mod.rs` — pop test module; checked test inclusion and helper scope; no issue found.
- `userspace-dp/src/afxdp/cos/queue_ops/pop_tests/ordering.rs` — ordering tests; checked FIFO/MQFQ, collision and cap ordering; no separate gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/pop_tests/rollback.rs` — rollback tests; checked multi-pop, partial commit, drop and snapshot restoration; no separate gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/pop_tests/snapshot_stack.rs` — snapshot-stack tests; checked stale-stack clearing and bounded growth; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/push.rs` — push/restore operations; checked front/back accounting, snapshot pairing, panic contracts and flow-fair promotion; no reachable packet leak found.
- `userspace-dp/src/afxdp/cos/queue_ops/tests/admission.rs` — queue admission tests; checked local/prepared and cap failure behavior; no separate gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/tests/bench.rs` — queue microbench tests; checked benchmark-only setup for invariant distortion; no production issue found.
- `userspace-dp/src/afxdp/cos/queue_ops/tests/bookkeeping.rs` — bookkeeping tests; checked byte/count/runnable symmetry; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/tests/cap_aware.rs` — cap-aware tests; checked all-over-cap fallback and finite/unbounded cap behavior; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/tests/flow_fair_enable.rs` — promotion tests; checked allocation/demotion thresholds and state preservation; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/tests/mod.rs` — queue-op test module; checked coverage wiring; no issue found.
- `userspace-dp/src/afxdp/cos/queue_ops/tests/promotion.rs` — promotion tests; checked queued-item migration and state initialization; no separate gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min.rs` — V-min coordination; checked publish-only-on-commit, stale peer slots, hard-cap escape and release behavior; no unreported stall or over-admit found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/cadence.rs` — cadence tests; checked publish cadence and prepared/local symmetry; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/hard_cap.rs` — hard-cap tests; checked escape activation, suspension and UMEM ownership; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/mod.rs` — V-min test module; checked inclusion; no issue found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/prepared_drain.rs` — prepared-drain tests; checked commit/rollback V-min publication; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/publish.rs` — publication tests; checked committed-vtime monotonicity; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/rejoiner.rs` — rejoin tests; checked peer-frontier reseed and stale participation; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/throttle.rs` — throttle tests; checked lag and suspension boundaries; no gap found.
- `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/vacate.rs` — vacate tests; checked NOT_PARTICIPATING publication and reentry; no gap found.

### CoS queue service, token buckets, and completion

- `userspace-dp/src/afxdp/cos/queue_service/drain.rs` — exact drain; checked scratch reuse, commit prefix, rollback and recycle ownership; no leak or duplicate send found.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs` — service selector/orchestrator; checked guarantee/surplus order, waterfill refund, visit bounds, allocations and queue mutation; no unreported correctness defect found.
- `userspace-dp/src/afxdp/cos/queue_service/service.rs` — service execution; checked phase progress and no-progress handling; no livelock found.
- `userspace-dp/src/afxdp/cos/queue_service/submit_local.rs` — local submission; checked partial insertion, frame ownership and retry construction; no loss found.
- `userspace-dp/src/afxdp/cos/queue_service/submit_prepared.rs` — prepared submission; checked in-flight recycle registration and partial insertion; no double recycle found.
- `userspace-dp/src/afxdp/cos/queue_service/tests/drain.rs` — drain tests; checked exact/non-exact, partial and no-progress cases; no separate gap found.
- `userspace-dp/src/afxdp/cos/queue_service/tests/mod.rs` — service test module; checked inclusion; no issue found.
- `userspace-dp/src/afxdp/cos/queue_service/tests/refund.rs` — refund tests; checked phase-1 debit restoration and honored-bit handling; no gap found.
- `userspace-dp/src/afxdp/cos/queue_service/tests/selector.rs` — selector tests; checked phase ordering, caps, exact demand and fairness; no gap found.
- `userspace-dp/src/afxdp/cos/queue_service/tests/sojourn.rs` — sojourn tests; checked committed-prefix-only sampling and rollback; no gap found.
- `userspace-dp/src/afxdp/cos/queue_service/tests/submit.rs` — submission tests; checked local/prepared partial commit and recycle; no gap found.
- `userspace-dp/src/afxdp/cos/queue_service/tests/wakeup.rs` — wakeup tests; checked timer-wheel/runnable transitions; no gap found.
- `userspace-dp/src/afxdp/cos/queue_service/tests/waterfill.rs` — waterfill tests; checked exact-fit, minimum quantum and multi-queue progress; no gap found.
- `userspace-dp/src/afxdp/cos/token_bucket.rs` — token buckets; checked refill dust, lease debit, u128 delay arithmetic, time rollback and cap semantics; no overflow or over-admit found.
- `userspace-dp/src/afxdp/cos/token_bucket_tests.rs` — token tests; checked fractional refill, saturation, shared leases and clock edges; no gap found.
- `userspace-dp/src/afxdp/cos/tx_completion.rs` — completion/accounting; checked retry restoration, lease consumption/release, timer-wheel work and interface activity; transient release-vector allocation is bounded by queue count and not promoted; no correctness defect found.
- `userspace-dp/src/afxdp/cos/tx_completion_tests.rs` — completion tests; checked local/prepared symmetry, retry, lease and activity transitions; no separate gap found.

### Forwarding and snapshot construction

- `userspace-dp/src/afxdp/forwarding/host_inbound.rs` — host-inbound classifier; checked strict/lenient known-zone default deny, interface overrides, IPv4/IPv6 services, control protocols and unknown tokens; the classifier itself fails closed for known zones; affected by A1-b2-01 through its caller-supplied ICMP byte.
- `userspace-dp/src/afxdp/forwarding/host_inbound_tests.rs` — host-inbound tests; checked no-stanza, override, family and global-control coverage; missing declared-datagram slack cases contribute to A1-b2-01.
- `userspace-dp/src/afxdp/forwarding/mod.rs` — forwarding state/helpers; checked zone-pair identity, VLAN logical resolution, route/neighbor and generated-reply helpers; no separate issue found.
- `userspace-dp/src/afxdp/forwarding/tests.rs` — forwarding tests; checked route, VLAN/RETH identity, host-local, NAT and generated-control coverage; no separate gap promoted.
- `userspace-dp/src/afxdp/forwarding_build/cos.rs` — CoS snapshot build; checked strict/lenient scheduler references, rate conversion and queue mapping; invalid references fail safe and no issue found.
- `userspace-dp/src/afxdp/forwarding_build/fib.rs` — FIB build; checked table scoping, next-hop inference and malformed routes; no fail-open route found.
- `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` — interface build; checked VLAN/RETH logical identity, zone/filter/host-inbound override keys and parent fallback; no separate mismatch found.
- `userspace-dp/src/afxdp/forwarding_build/mod.rs` — snapshot orchestration; checked validation-before-publication, pass order and previous-state retention; no partial-publication issue found.
- `userspace-dp/src/afxdp/forwarding_build/tests.rs` — snapshot tests; checked corrupt snapshot, logical interface, policy, CoS and compatibility paths; no separate gap promoted.
- `userspace-dp/src/afxdp/forwarding_build/tunnels.rs` — tunnel build; checked malformed references, liveness and route identity; no issue found.
- `userspace-dp/src/afxdp/forwarding_build/validated.rs` — validated state wrapper; checked construction boundary and publication invariant; no bypass found.
- `userspace-dp/src/afxdp/forwarding_build/wg.rs` — WireGuard build; checked peer/interface mapping and malformed state; no issue found.
- `userspace-dp/src/afxdp/forwarding_build/zones.rs` — zone build; checked duplicate/reserved IDs, known-zone host-inbound default deny, reject buckets and scoped maps; corrupt IDs reject before publication and no issue found.

### Frame construction, inspection, mutation, and segmentation

- `userspace-dp/src/afxdp/frame/build/ipv4.rs` — IPv4 forward build; checked IHL/TTL, fragment-safe NAT, checksum and expected-port enforcement; no separate issue found.
- `userspace-dp/src/afxdp/frame/build/ipv6.rs` — IPv6 forward build; checked extension offsets, hop limit, fragments, NAT and checksum; no separate issue found.
- `userspace-dp/src/afxdp/frame/build/mod.rs` — frame-build orchestrator; checked L2/VLAN sizing, copy bounds and family dispatch; no issue found.
- `userspace-dp/src/afxdp/frame/byte_writes.rs` — byte writers; checked endian offsets and bounds; no issue found.
- `userspace-dp/src/afxdp/frame/byte_writes_tests.rs` — writer tests; checked boundary and endian cases; no gap found.
- `userspace-dp/src/afxdp/frame/checksum.rs` — checksum core; checked odd lengths, pseudoheaders, zero-checksum rules, incremental adjustment and integer bounds; no defect found.
- `userspace-dp/src/afxdp/frame/generated.rs` — generated replies; checked reflection, suppression, minimum frame sizing and L2/L3 source rules; no separate issue found.
- `userspace-dp/src/afxdp/frame/generated_tests.rs` — generated-frame tests; checked RST/ICMP feasibility and malformed inputs; no separate gap found.
- `userspace-dp/src/afxdp/frame/headers.rs` — header writers; checked VLAN and IP/UDP lengths/checksums; no issue found.
- `userspace-dp/src/afxdp/frame/headers_tests.rs` — header tests; checked tagged/untagged and family variants; no gap found.
- `userspace-dp/src/afxdp/frame/inspect.rs` — frame inspection and filter match inputs; checked declared lengths, metadata fallback, extensions, fragments and L4 presence; A1-b2-01: ICMP/fragment match inputs still read Ethernet slack outside the declared datagram.
- `userspace-dp/src/afxdp/frame/inspect_tests.rs` — inspection regression tests; checked declared-length port parsing and slack cases; coverage does not exercise the affected filter-match inputs in A1-b2-01.
- `userspace-dp/src/afxdp/frame/mod.rs` — frame mutation/orchestration; checked UMEM offset ownership, VLAN shifts, NAT, declared lengths, flowless paths and generated classification; no separate issue found.
- `userspace-dp/src/afxdp/frame/prop_tests/inspect.rs` — inspection properties; checked panic/bounds and parser consistency domains; declared-slack semantic oracle gap is part of A1-b2-01.
- `userspace-dp/src/afxdp/frame/prop_tests/mod.rs` — property-test module; checked corpus wiring; no issue found.
- `userspace-dp/src/afxdp/frame/prop_tests/oracle.rs` — property oracles; checked independent checksum/parser assumptions; no separate issue found.
- `userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs` — rewrite differential properties; checked descriptor/generic parity and NAT/fragment exclusions; no gap found.
- `userspace-dp/src/afxdp/frame/prop_tests/segment.rs` — segmentation properties; checked segment lengths, sequence/checksum and conservation; no gap found.
- `userspace-dp/src/afxdp/frame/prop_tests/strategies.rs` — generators; checked malformed/header boundary generation; no production issue found.
- `userspace-dp/src/afxdp/frame/rewrite/ipv4.rs` — IPv4 descriptor rewrite; checked bounds, TTL, ports and checksum deltas; no issue found.
- `userspace-dp/src/afxdp/frame/rewrite/ipv6.rs` — IPv6 descriptor rewrite; checked extensions, hop limit, ports and checksum deltas; no issue found.
- `userspace-dp/src/afxdp/frame/rewrite/mod.rs` — rewrite orchestrator; checked NAT64/NPTv6 fallback and unsafe UMEM borrow; no ownership or fail-open issue found.
- `userspace-dp/src/afxdp/frame/tcp.rs` — TCP helpers; checked option walking, MSS clamp, flags/window and truncated headers; no issue found.
- `userspace-dp/src/afxdp/frame/tcp_segmentation.rs` — TSO segmentation; checked sizing, sequence/flags, checksums, ownership and tunnel encapsulation; no leak or malformed segment found.
- `userspace-dp/src/afxdp/frame/tcp_tests.rs` — TCP tests; checked malformed options, MSS and checksum edges; no separate gap found.
- `userspace-dp/src/afxdp/frame/tests.rs` — frame integration tests; checked NAT, VLAN, fragments, filters, generated replies and declared slack; flex slices are covered, but ICMP/fragment scalar inputs are not, supporting A1-b2-01.
- `userspace-dp/src/afxdp/frame/wg.rs` — WireGuard frame handling; checked padding/MTU, checksum, encryption output sizing and ownership; no issue found.
- `userspace-dp/src/afxdp/frame/wg_tests.rs` — WireGuard frame tests; checked v4/v6, padding, MTU and checksum cases; no gap found.

### Embedded ICMP and mirroring

- `userspace-dp/src/afxdp/icmp_embed/builders.rs` — embedded-ICMP reverse builders; checked quote bounds, NAT reversal, checksums and fragment handling; no separate issue found.
- `userspace-dp/src/afxdp/icmp_embed/mod.rs` — embedded-ICMP dispatch; checked outer error type gate, session/NAT lookup and locking; physical-slack trust is related to A1-b2-01 but no distinct finding split.
- `userspace-dp/src/afxdp/icmp_embed/nat_match_v4.rs` — v4 embedded NAT match; checked forward/reverse tuple and return resolution; no separate issue found.
- `userspace-dp/src/afxdp/icmp_embed/nat_match_v6.rs` — v6 embedded NAT match; checked NPTv6/NAT64 and extension-header paths; no separate issue found.
- `userspace-dp/src/afxdp/icmp_embed/parse.rs` — embedded parser; checked IHL, extension bounds, fragments and quote lengths; malformed declared-inner-length trust is the same packet-boundary class as A1-b2-01 and is included in its fix direction.
- `userspace-dp/src/afxdp/icmp_embed/return_resolution.rs` — return route helper; checked table/neighbor resolution and failure disposition; no issue found.
- `userspace-dp/src/afxdp/icmp_embed/session_match.rs` — embedded session matching; checked canonical/reverse/NAT lookup and lifetime touch; no separate issue found.
- `userspace-dp/src/afxdp/mirror/fast_path.rs` — mirror clone path; checked sampling, admission reservation, allocation, UMEM copy and recycle; no leak or unbounded queue found.
- `userspace-dp/src/afxdp/mirror/mod.rs` — mirror configuration/sampling; checked logical-interface resolution and counter wrap; no issue found.
- `userspace-dp/src/afxdp/mirror/mod_tests.rs` — mirror tests; checked same/cross worker, queue/full/frame failures, VLAN identity and sampling; no gap found.
- `userspace-dp/src/afxdp/mirror/resolver.rs` — mirror target resolver; checked queue fallback, reservation and CoS selection; no issue found.

### Poll descriptor decisions and generated rejects

- `userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs` — SYN-cookie replies; checked budget, logical egress classification, output filter and ownership; no separate issue found.
- `userspace-dp/src/afxdp/poll_descriptor/cookie_reply_tests.rs` — cookie tests; checked budget/output-filter/VLAN cases; no gap found.
- `userspace-dp/src/afxdp/poll_descriptor/debug_log_throttle.rs` — debug throttling; checked arithmetic and hot-path state; no issue found.
- `userspace-dp/src/afxdp/poll_descriptor/filter.rs` — filter and host-local ordering; checked ingress/PBR/lo0/output order, counters/logs, Junos-host and generated reply classification; consumes A1-b2-01 match inputs, no distinct defect found.
- `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` — flow-cache hit path; checked policy/zone/HA generation validity, neighbor epoch, TTL order, filter replay, NAT and UMEM ownership; no stale-permit or double recycle found.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — packet pipeline; traced screen, IPsec, input filter, DNAT, route/PBR, zone policy/global/scoped-global/default/Junos-host, host-inbound, NAT, sessions/cache and flowless order for v4/v6/VLAN; A1-b2-01 reaches policy/filter/host-inbound consumers; no separate ordering defect found.
- `userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs` — NAT failure handling; checked fail-closed pool errors and event/counter parity; no issue found.
- `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` — deny/reject synthesis; checked feasibility, VLAN source, budget, zone bucket, output filter and counters; A1-b2-02: output-filter-dropped replies consume the shared zone token first.
- `userspace-dp/src/afxdp/poll_descriptor/reject_reply_tests.rs` — reject tests; checked policy/filter source split, malformed/fragment suppression, per-zone buckets and output filters; missing assertion that output-filter drops preserve tokens is A1-b2-02.
- `userspace-dp/src/afxdp/poll_descriptor/rx_telemetry.rs` — RX telemetry; checked length/counter accounting and batch flush behavior; no correctness issue found.


## A1-b3


Dimensions: `CS` correctness/security and fail-open/false-deny; `MC` memory/concurrency/integer/lifetime; `VP` vSRX/Junos parity; `HP` hot-path allocation/locking/cache work; `MT` modularity/tests. Every assigned path is ledgered below.

### Session import, promotion, and Z5 authorization lifecycle

- `userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs` - CS/MC: NAT/NAT64 reservation release and BPF alias delete are paired; no new double-release or stale-alias root found.
- `userspace-dp/src/afxdp/session_glue/commands/demote_owner_rgs.rs` - CS/VP: re-resolves HA disposition, preserves fabric-ingress zone identity, republishes, and deduplicates cancellation; no denied-to-forward transition found.
- `userspace-dp/src/afxdp/session_glue/commands/export_owner_rg_sessions.rs` - CS/MC: defers bulk export to drain-as-you-export and deduplicates RGs; bounded ring-overflow fix is intact.
- `userspace-dp/src/afxdp/session_glue/commands/mod.rs` - MT: handler exports and test-only refresh seam match dispatcher ownership; no divergent variant wiring found.
- `userspace-dp/src/afxdp/session_glue/commands/refresh_owner_rgs.rs` - CS/VP: full HA-managed scan handles split-RG companions and recomputes local-replace from current owner; no standby LocalDelivery pass-to-kernel bypass found.
- `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs` - CS/VP: local forwarding and NAT reservations are rebuilt before publish; authorization identity is accepted without a receiving-snapshot binding, contributing `A1-b3-F001`.
- `userspace-dp/src/afxdp/session_glue/mod.rs` - CS/MC/HP: lookup scope precedence, transient translated-hit purge, reverse materialization, command ordering, poison recovery, and flow-cache HA enforcement checked; no fresh alias or owner-RG bypass.
- `userspace-dp/src/afxdp/session_glue/promote.rs` - CS/MC: promotion requires promotable origin plus ForwardCandidate and republishes/replicates after in-place promotion; no unauthorized origin promotion found, but it consumes the unbound metadata in `A1-b3-F001`.
- `userspace-dp/src/afxdp/session_glue/tests.rs` - MT: 86 tests cover local/shared scope, demote/refresh, split RG, prewarm, poison recovery, NAT collisions, cap behavior, event deltas, and LocalDelivery publish mode; missing negative stale/unknown-zone promotion test noted in `A1-b3-F001`.

### Egress output filtering, CoS selection, TX, and recycle ownership

- `userspace-dp/src/afxdp/tx/cos_classify.rs` - CS/VP/HP: post-NAT family/tuple, output terminal actions, reject subset, ingress modifier precedence, policers, BA reclassification, and generated replies checked; known flowless-output-filter bypass is deduped to prior codex-review-179, no new root.
- `userspace-dp/src/afxdp/tx/cos_classify_tests.rs` - MT: 55 tests cover counters, terminal discard/reject, NAT64 family, per-packet flags, PBR modifiers, generated replies, CoS rewrites, and PCP bounds; no fresh semantic gap beyond deduped flowless behavior.
- `userspace-dp/src/afxdp/tx/dispatch/cos.rs` - CS/HP: requested/default queue routing, shared-exact policy, owner handoff, and overflow semantics checked; bounded inbox drops remain explicit.
- `userspace-dp/src/afxdp/tx/dispatch/mod.rs` - CS/MC/VP: ingress recycle on all exits, segmentation/PTB, tunnel transforms, output-filter decision consumption, and CoS enqueue ordering checked; no new plaintext or double-recycle path.
- `userspace-dp/src/afxdp/tx/dispatch/shared_recycle.rs` - MC: slot lookup validates identity then scans stale lookup; unknown slot drops are counted, no misroute/double-fill found.
- `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` - CS/MC: declared frame extraction and reinjection disposition allowlist are bounded and fail closed; no new tunnel plaintext fallback.
- `userspace-dp/src/afxdp/tx/dispatch/tests/cos_shared_exact.rs` - MT: shared exact/default/non-exact/unknown queue routing matrix is present; negative result.
- `userspace-dp/src/afxdp/tx/dispatch/tests/enqueue_failure.rs` - MT/MC: mirror, no-binding, copy fallback, repeated conservation, oversize, and tuple mismatch recycle tests cover ownership exits; negative result.
- `userspace-dp/src/afxdp/tx/dispatch/tests/mod.rs` - MT: fixtures preserve live/prebuilt request and ingress recycle accounting; negative result.
- `userspace-dp/src/afxdp/tx/dispatch/tests/ptb.rs` - MT/VP: PTB suppression/emission, output discard, trigger-tuple counterfactual, DSCP, and parse-fail-closed tests are present.
- `userspace-dp/src/afxdp/tx/dispatch/tests/segmentation.rs` - MT: VLAN offset, MTU boundary, miss observability/rate cap, and oversized cases covered; negative result.
- `userspace-dp/src/afxdp/tx/dispatch/tests/shared_recycle.rs` - MT/MC: stale lookup scan, unknown/out-of-range slot, and error accounting covered; negative result.
- `userspace-dp/src/afxdp/tx/drain/mod.rs` - CS/HP: CoS-bound partition scans full deque and preserves failed-item order; no cap bypass found.
- `userspace-dp/src/afxdp/tx/drain/phase_backup.rs` - CS/HP: backup path excludes CoS-bound leftovers and accounts drops; no unshaped escape found.
- `userspace-dp/src/afxdp/tx/drain/phase_shaped.rs` - CS/HP: shaped service gates and accounting checked; no idle-spin or queue-order regression found.
- `userspace-dp/src/afxdp/tx/drain/phase_trivial.rs` - CS: trivial non-CoS drain delegation preserves retry behavior; negative result.
- `userspace-dp/src/afxdp/tx/drain/tests.rs` - MT: mixed-head scan, rescue, default queue, retry order, and idle guards covered; negative result.
- `userspace-dp/src/afxdp/tx/mod.rs` - MT: exports match dispatch/drain/transmit ownership; no duplicate implementation.
- `userspace-dp/src/afxdp/tx/rings.rs` - MC/HP: completion stamps, outstanding gauge, prepared recycle map, fill/free ownership, and kick behavior checked; no double ownership found.
- `userspace-dp/src/afxdp/tx/stats.rs` - MC: latency stamp indexing and completion accounting are bounds checked; no integer/lifetime defect found.
- `userspace-dp/src/afxdp/tx/tcp_segmentation.rs` - CS/MC/HP: segment count/capacity, sequence wrap, checksum/flags, output ownership, and failure unwind checked; no segment leak or filter bypass found.
- `userspace-dp/src/afxdp/tx/test_support.rs` - MT: fixtures only; production invariants not weakened.
- `userspace-dp/src/afxdp/tx/transmit/finalise.rs` - HP/MC: partial-prefix ownership is correct, but overload recovery allocates, contributing `A1-b3-F002`.
- `userspace-dp/src/afxdp/tx/transmit/mod.rs` - MC/HP: local and prepared orchestration, partial insert, stamp-after-commit, retry ordering, and kicks checked; same overload allocation class as `A1-b3-F002`.
- `userspace-dp/src/afxdp/tx/transmit/rewrite.rs` - MC: unsafe mutable slice is range checked and every staged orphan is recycled; DSCP mutation failure is counted.
- `userspace-dp/src/afxdp/tx/transmit/stage.rs` - MC: oversize offender plus staged prefix are recycled and counted exactly once; negative result.
- `userspace-dp/src/afxdp/tx/transmit/verify.rs` - MC: post-rewrite range verification drains/recycles all staged entries on failure; negative result.
- `userspace-dp/src/afxdp/tx/transmit/write.rs` - MC/HP: descriptor prefix commit and post-commit stamps align; no stamp on unaccepted suffix.
- `userspace-dp/src/afxdp/tx/transmit_tests.rs` - MT: foreign/local recycle routing and oversized unwind covered; no ring-full allocation/partial-prepared finalise test, supporting `A1-b3-F002`.

### CoS runtime types and shared lease invariants

- `userspace-dp/src/afxdp/types/cos.rs` - MC/HP: queue state, fixed RR ring, flow-fair arrays, counters, sojourn, token arithmetic, and memory ceilings checked; no fresh wrap/cap bug.
- `userspace-dp/src/afxdp/types/cos_sojourn_tests.rs` - MT: zero sentinel, EWMA/peak, window flip, idle expiry, and clock skew covered.
- `userspace-dp/src/afxdp/types/forwarding.rs` - CS/VP: forwarding/filter/zone/HA/WG/CoS snapshot fields and defaults checked; no widening default found in assigned surface.
- `userspace-dp/src/afxdp/types/mod.rs` - MC: metadata layout, zone IDs, packet metadata, owner indexes, and helper conversions checked; no truncation or aliasing defect.
- `userspace-dp/src/afxdp/types/runtime.rs` - CS/MC: validation/HA command and binding-plan carriers checked; command variants preserve explicit ownership.
- `userspace-dp/src/afxdp/types/shared_cos_lease/backlog.rs` - MC/HP: atomic per-slot bytes and residual tokens are bounded/saturating; no index overflow.
- `userspace-dp/src/afxdp/types/shared_cos_lease/epoch.rs` - MC: packed generation/grant state and seqlock ordering checked; no torn publication found.
- `userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs` - MC/HP: aggregate cap, carry, equal-flow, release recredit, and worker bounds checked; known fail-open modes are explicit/telemetried.
- `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs` - MT: split module exports preserve ownership; negative result.
- `userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs` - MC: tag/payload publication and active-flow max semantics checked; no backward tag write.
- `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs` - MC/HP: carry regimes, bypass decay, and rotation ledger checked; no new overgrant.
- `userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs` - MT: 97 tests cover serial/concurrent caps, wrap, carry, equal-flow, bypass, rehydrate, release, and seqlock; broad negative result.
- `userspace-dp/src/afxdp/types/shared_cos_lease/vtime.rs` - MC: not-participating sentinel and floor publication are clamped; no sentinel collision.
- `userspace-dp/src/afxdp/types/tx.rs` - MC: Live/Owned/Prebuilt and PreparedTxRecycle encode original-frame ownership explicitly; no ambiguous recycle conversion found.

### UMEM mapping, live state, and observability

- `userspace-dp/src/afxdp/umem/debug_state.rs` - MC/HP: cadence, V_min scratch flush, idle snapshots, and counters checked; no stale nonzero publication.
- `userspace-dp/src/afxdp/umem/mmap.rs` - MC: zero/align overflow, registered-length bounds, mmap/munmap lifetime, and single-writer unsafe mutation contract checked.
- `userspace-dp/src/afxdp/umem/mmap_tests.rs` - MT: zero and rounded-length overflow rejection covered.
- `userspace-dp/src/afxdp/umem/mod.rs` - MC/HP: WorkerUmem ownership, bounded redirect inbox, admission CAS, counters, snapshots, status atomics, and pending deltas checked; no fresh frame leak/double-free.
- `userspace-dp/src/afxdp/umem/profile.rs` - HP: owner/peer cacheline isolation and histogram atomics checked; no new false sharing beyond documented layout.
- `userspace-dp/src/afxdp/umem/snapshot.rs` - MC: relaxed multi-atomic snapshot skew is documented/bounded; fields are propagated.
- `userspace-dp/src/afxdp/umem/tests/debug_state.rs` - MT: idle/non-idle cadence and V_min scratch zeroing covered.
- `userspace-dp/src/afxdp/umem/tests/latency_buckets.rs` - MT: bucket boundaries, saturation, sampling, and seed behavior covered.
- `userspace-dp/src/afxdp/umem/tests/mmap_area.rs` - MT/MC: registered length, not rounded mapping length, gates access.
- `userspace-dp/src/afxdp/umem/tests/mod.rs` - MT: shared fixtures only; negative result.
- `userspace-dp/src/afxdp/umem/tests/snapshot_propagation.rs` - MT: owner profile, cacheline alignment, and drop counters propagate.
- `userspace-dp/src/afxdp/umem/tests/tx_inbox.rs` - MT: soft-cap drop and append semantics covered.
- `userspace-dp/src/afxdp/umem/tests/tx_kick_latency.rs` - MT: buckets, retry, underflow sentinel, and cross-thread skew covered.
- `userspace-dp/src/afxdp/umem/tests/tx_submit_latency.rs` - MT/MC: partial-prefix stamps, retry unwind, OOB offsets, Rc single-writer ownership, and skew covered.

### WireGuard cryptography, routing identity, and timers

- `userspace-dp/src/afxdp/wg/allowed_ips.rs` - CS/VP/HP: global LPM then peer comparison, overlap, duplicate, family, and prefix bounds checked; linear scan is config-bounded.
- `userspace-dp/src/afxdp/wg/cookie.rs` - CS/MC: MAC2, rotating CSPRNG secrets, source/global budgets, nonce AEAD, constant-time compare, and table cap checked; no new amplification or weak-random path.
- `userspace-dp/src/afxdp/wg/cookie_tests.rs` - MT: source binding, rotation, RNG failure, budgets, initiator decrypt, and tamper cases covered.
- `userspace-dp/src/afxdp/wg/counters.rs` - MT/MC: every encap/decap error maps to a counter; keepalive split checked.
- `userspace-dp/src/afxdp/wg/dscp.rs` - VP: DSCP-to-TOS masks to six bits; ECN handling is intentionally outside this helper.
- `userspace-dp/src/afxdp/wg/engine.rs` - CS/MC/HP: peer snapshots, key slots, encap padding/counter ceiling, AEAD, replay-after-auth, AllowedIPs, length trimming, wipe-on-error, and age gates checked; prior replay-window/keepalive/global-edge findings deduped.
- `userspace-dp/src/afxdp/wg/engine_tests.rs` - MT: reconcile/index/session install and internal bounds covered.
- `userspace-dp/src/afxdp/wg/framing.rs` - CS: canonical type/reserved bytes, LE indices/counters, and minimum length checked.
- `userspace-dp/src/afxdp/wg/handshake.rs` - CS: message sizes, MAC1, canonical type word, and output bounds checked.
- `userspace-dp/src/afxdp/wg/handshake_session.rs` - CS/MC: reservation maps, cookie state, Noise transitions, TAI64N replay, index collision, and install serialization checked.
- `userspace-dp/src/afxdp/wg/handshake_tests.rs` - MT: KATs, layout, canonical reserved bytes, MACs, length, and round trips covered.
- `userspace-dp/src/afxdp/wg/mod.rs` - MT/CS: constants, protocol prologue, zero PSK, and exports checked; no secret Debug leak.
- `userspace-dp/src/afxdp/wg/mss.rs` - VP/MC: outer-family overhead, padding/tag allowance, underflow saturation, and clamp boundaries covered.
- `userspace-dp/src/afxdp/wg/peer.rs` - MC: three-slot key lifecycle, high-water timestamp, activity atomics, and lock order checked; no orphaned demux index in assigned path.
- `userspace-dp/src/afxdp/wg/scratch.rs` - HP: fixed preallocated buffers avoid per-call allocation; bounds derive from engine maximum.
- `userspace-dp/src/afxdp/wg/session.rs` - CS/MC: atomic TX counter ceiling, key confirmation, replay bitmap/window arithmetic, and age constants checked; 64-window concern is prior codex-review-177 duplicate.
- `userspace-dp/src/afxdp/wg/tai64n.rs` - CS/MC: monotonic whitening/high-water and wrap arithmetic checked; no replay rollback.
- `userspace-dp/src/afxdp/wg/tai64n_tests.rs` - MT: encode/order/rollback/reseed and concurrency cases covered.
- `userspace-dp/src/afxdp/wg/tests.rs` - MT: 76 integration tests cover encap/decap, replay, AllowedIPs, confirmation, timers, keepalives, key slots, truncation, and counters; prior multi-peer keepalive issue deduped.
- `userspace-dp/src/afxdp/wg/timers.rs` - CS/MC: T6/T7/T8 precedence, future-deadline sentinel, expiry under reconcile lock, and pacing checked; engine-global edge issue is prior duplicate.

### Worker lifecycle, CoS status, and binding ownership

- `userspace-dp/src/afxdp/worker/bind_meta.rs` - MC: binding metadata carrier has stable scalar ownership; negative result.
- `userspace-dp/src/afxdp/worker/bpf_maps.rs` - MC: borrowed FD grouping only; no lifetime extension.
- `userspace-dp/src/afxdp/worker/cos/interface_row.rs` - CS/MT: interface status aggregation and defaults checked; no hidden queue omission.
- `userspace-dp/src/afxdp/worker/cos/mod.rs` - HP/MC: fast maps, owner profile snapshot/merge, reset, and runtime build checked; no per-packet lock introduced.
- `userspace-dp/src/afxdp/worker/cos/queue_row.rs` - CS: queue telemetry and waterfill/equal-flow fields aggregate with intended sum/max semantics.
- `userspace-dp/src/afxdp/worker/cos/status.rs` - CS: status projection preserves queue identity and counters; negative result.
- `userspace-dp/src/afxdp/worker/cos/tests.rs` - MT: 27 tests cover build, owner selection, status merge, reset, and config change; negative result.
- `userspace-dp/src/afxdp/worker/cos_state.rs` - MC: worker-owned CoS maps and counters have clear ownership; negative result.
- `userspace-dp/src/afxdp/worker/flow_cache_state.rs` - CS/MC: per-binding cache ownership and scratch sets are isolated; negative result.
- `userspace-dp/src/afxdp/worker/lifecycle.rs` - MC/HP: poll, TX drain, completion reap, shared recycle application, fill return, and teardown ordering checked; no outstanding session left running.
- `userspace-dp/src/afxdp/worker/loop_body/debug_report.rs` - CS: status counters and diagnostics are snapshot-only; no hot-path policy decision.
- `userspace-dp/src/afxdp/worker/loop_body/mod.rs` - CS/MC/HP: snapshot publication, input-filter session purge, CoS reset, chunked HA export, poll ordering, and debug cadence checked; no fresh policy/HA cache bypass.
- `userspace-dp/src/afxdp/worker/loop_body/setup.rs` - MC: binding setup and initial map/runtime publication checked; no partially initialized worker exposure.
- `userspace-dp/src/afxdp/worker/mod.rs` - MC/HP: BindingWorker construction, reserved frames, shared UMEM role, hash routing, status snapshot, and ownership fields checked.
- `userspace-dp/src/afxdp/worker/scratch.rs` - HP: vectors are preallocated and reused; overload-only TX allocations remain in `A1-b3-F002`, not here.
- `userspace-dp/src/afxdp/worker/telemetry.rs` - MC: worker-local counters only; no cross-thread unsynchronized mutation.
- `userspace-dp/src/afxdp/worker/timers.rs` - MC: monotonic deadlines and cadence fields checked; negative result.
- `userspace-dp/src/afxdp/worker/tx_counters.rs` - CS: batch-to-live TX counter flush checked; no double count found.
- `userspace-dp/src/afxdp/worker/tx_pipeline.rs` - MC: pending queues, free frames, outstanding count, recycle map, and stamps have single-worker ownership.
- `userspace-dp/src/afxdp/worker/xsk_rings.rs` - MC: ring bundle lifetime and ownership are structural; negative result.
- `userspace-dp/src/bin/fairness-eval.rs` - MT: thin diagnostic entry point; 60 fairness binary tests passed, no forwarding-path effect.

### Event stream, session-sync wire, and producer backpressure

- `userspace-dp/src/event_stream/codec/codec_tests.rs` - MT: 24 tests cover frame constants/layout, zone width, policy metadata, RT_FLOW, lengths, and round trips; no zone-snapshot identity negative test (`A1-b3-F001`).
- `userspace-dp/src/event_stream/codec/decode.rs` - CS/MC: exact 160-byte event length, kind/family consistency, endian reads, and optional zero IP checked.
- `userspace-dp/src/event_stream/codec/mod.rs` - MT: codec exports and session-frame classification are coherent.
- `userspace-dp/src/event_stream/codec/rt_flow.rs` - CS/VP: session create/close, deny/screen/filter wire slots, policy/application IDs, counters, and stable ID checked.
- `userspace-dp/src/event_stream/codec/session_sync.rs` - CS/VP: zone/policy/NAT64 metadata encoding and lengths checked; no receiving-snapshot generation accompanies zone IDs, contributing `A1-b3-F001`.
- `userspace-dp/src/event_stream/codec/wire.rs` - CS/MC: type constants, additive payload sizing, address writers, disposition encoding, and header bounds checked.
- `userspace-dp/src/event_stream/mod.rs` - MC/HP: bounded sync channel, sequence allocation/rollback, replay/drain, lossless timeout, and event/session separation checked; full-suite backlog test flaked once and passed isolated.
- `userspace-dp/src/event_stream/producer.rs` - CS/HP: per-kind/per-zone token buckets plus shared reserve are bounded; security-event drops are counted and cannot consume session reserve.
- `userspace-dp/src/event_stream/producer_tests.rs` - MT: rate limits, kind isolation, shared reserve, full/disconnect drops, and sequence rollback covered.

### Cross-owner handoff notes

- A1/policy-control owner: `A1-b3-F001` crosses the Rust session-sync encoder/importer into Go cluster apply and policy-rematch. The receiving side should validate zone identity and authorization generation before promotion; do not duplicate this as a generic policy-rematch finding.
- Packet-pipeline owner: the embedded-ICMP NAT reversal caller in `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2521` classifies a prebuilt rewritten frame with trigger metadata rather than `classify_generated_reply`; this is outside the batch and needs owner validation against post-rewrite output-filter tuple semantics before filing.
- Existing duplicate suppressed: flowless TX skips all output filters (`prior:codex-review-179.md`), including the non-first-fragment compatibility path; not re-reported.
- Existing duplicates suppressed: WireGuard 64-packet replay window, authenticated multi-peer keepalive endpoint learning, engine-global handshake/rekey edges, and canonical reserved-word parsing are in prior codex reviews 175/177.


## A1-b4


- `userspace-dp/src/event_stream/tests/backpressure.rs` — event-stream tests; checked bounded channels, lossless-vs-telemetry pressure, disconnect/reconnect ownership, and counters. Negative: exercises blocking and drop accounting without exposing a deadlock, unbounded allocation, sequence burn, or policy-event loss misclassification.
- `userspace-dp/src/event_stream/tests/control_frames.rs` — event-stream tests; checked frame lengths, ACK/control decode, malformed/truncated input, and byte order. Negative: positive and hostile control-frame cases preserve bounded parsing and reject malformed frames.
- `userspace-dp/src/event_stream/tests/drain.rs` — event-stream tests; checked replay draining, disconnect transitions, queue budget release, and resource lifetime. Negative: no stranded budget or replay ordering hole found.
- `userspace-dp/src/event_stream/tests/mod.rs` — event-stream test harness; checked fixture construction, module coverage, zone/policy metadata, and shared helpers. Negative: fixtures do not mask production defaults relevant to the assertions.
- `userspace-dp/src/event_stream/tests/replay_budget.rs` — event-stream tests; checked sequence monotonicity, concurrent send ordering, eviction, ACK trim, full-channel loss, and accounting. Negative: explicit concurrency and loss tests cover the hostile budget paths.
- `userspace-dp/src/event_stream/tests/rt_flow.rs` — RT_FLOW tests; checked session open/close pairing, timestamps, app/policy IDs, ifindex, rate limiting, and counters. Negative: event attribution remains consistent for permit-session lifecycle records.
- `userspace-dp/src/fairness.rs` — fairness math; checked zero totals, worker bounds, floating-point finiteness, allocation, and HFT cold-tool isolation. Negative: bounded O(workers) aggregation and explicit zero guards; no dataplane hot-path use.
- `userspace-dp/src/fairness_tests.rs` — fairness tests; checked balanced/skewed/zero fixtures and threshold edges. Negative: covers positive and false-pass/false-fail boundary cases.
- `userspace-dp/src/hot_hash_seed.rs` — hash seeding; checked getrandom syscall retries, entropy failure, fallback uniqueness, and hot-map collision resistance. Negative: bounded attempts and per-process/time fallback avoid a deterministic all-zero seed; no packet-path syscall.
- `userspace-dp/src/hot_hash_seed_tests.rs` — hash-seed tests; checked seed nonzero/variation and test seam. Negative: narrow coverage is adequate for deterministic helper behavior; OS failure remains covered structurally.
- `userspace-dp/src/io_uring_write.rs` — shared writer; checked SQE/CQE ownership, stale completions, EINTR, partial writes, offset bounds, and buffer lifetime. Negative/new-finding result: the 4096-retry residual in-flight buffer lifetime risk is already recorded under prior-root #2297 review evidence and is not a new finding.
- `userspace-dp/src/io_uring_write_tests.rs` — io_uring tests; checked interrupted waits, stale/mismatched CQEs, permanent/transient errors, short packet writes, and retry classification. Negative: hostile fakes pin the intended state machine; the documented retry-ceiling residual is duplicate evidence.
- `userspace-dp/src/ip_proto.rs` — protocol mapping; checked normalization, numeric range, aliases, and L4-port classification. Negative: one shared resolver prevents policy/filter parser skew for represented protocols.
- `userspace-dp/src/main.rs` — process entry; checked argument dispatch, fairness subcommand isolation, server startup error propagation, and teardown. Negative: no silent startup success or forwarding bypass found.
- `userspace-dp/src/main_tests.rs` — top-level tests; checked CLI/config boundaries, snapshot protocol fixtures, forwarding startup, and malformed state. Negative: broad positive/negative coverage; no uncovered assigned-source defect isolated.
- `userspace-dp/src/nat64_tests.rs` — NAT64 tests; checked v4/v6 translation, VLAN offsets, fragments, ICMP, checksum/length bounds, policy tuple order, allocation, HA carriage, and no-allocation write paths. Negative: extensive malformed and fail-closed cases cover the assigned NAT64 surface.
- `userspace-dp/src/nptv6_tests.rs` — NPTv6 tests; checked prefix lengths/host bits, overlap rejection, checksum neutrality, composition, and round trips. Negative: invalid snapshots fail closed and valid translations preserve address/checksum invariants.
- `userspace-dp/src/policy.rs` — zone-policy compiler/evaluator; checked strict/lenient backstops, exact/wildcard/scoped-global/default/Junos-host precedence, app sets, fragments, mixed NAT64 families, counters, and unknown zones. Negative: malformed actions/addresses/apps/zones reject snapshots; flowless overlapping denies override later permits; no new bypass survived trace.
- `userspace-dp/src/policy_snapshot_error.rs` — policy/filter integrity errors; checked error completeness, diagnostics, ownership, and caller propagation. Negative: variants cover the parser/compiler rejection sites inspected; no error is silently converted to permit at this layer.
- `userspace-dp/src/policy_tests.rs` — policy tests; checked exact/global/scoped/wildcard/default/Junos-host, applications/sets, ICMP, fragments, v4/v6/NAT64, counters, malformed snapshots, and identity collisions. Negative: strong permit and deny coverage; deferred initial-snapshot validation is outside this unit suite.
- `userspace-dp/src/prefix.rs` — prefix wrappers; checked network normalization and contains semantics. Negative: typed `ipnet` representation avoids ad hoc masking and family confusion.
- `userspace-dp/src/prefix_set.rs` — prefix sets; checked MatchAny/MatchNone distinction, v3/legacy empty semantics, trie bounds, and family separation. Negative: explicit constructors preserve fail-closed empty-set semantics used by policy/filter compilers.
- `userspace-dp/src/prefix_set_tests.rs` — prefix-set tests; checked empty, wildcard, dedup, containment, and v4/v6 edges. Negative: positive and negative membership semantics are pinned.
- `userspace-dp/src/slowpath.rs` — TUN slow path; checked packet length, io_uring fallback classification, fd/resource lifetime, bounded queues, and reinjection ownership. Negative: partial/ambiguous writes drop instead of duplicate-transmitting; no policy decision is made here.
- `userspace-dp/src/slowpath_tests.rs` — slow-path tests; checked short writes, fallback, queue pressure, framing, and teardown. Negative: hostile writer outcomes cover duplicate/corrupt reinjection risks.
- `userspace-dp/src/state_writer.rs` — persistence writer; checked atomic temp/rename, stale-temp ownership, PID reuse, fsync/error propagation, locks, and shutdown. Negative: writes are serialized and stale cleanup uses PID plus process start; no cross-owner deletion found.
- `userspace-dp/src/state_writer_tests.rs` — state-writer tests; checked atomic replacement, failures, stale/live temp files, mode/status, and concurrency. Negative: positive/negative filesystem cases cover the assigned lifetime invariants.
- `userspace-dp/src/tcp_flags.rs` — TCP flag predicates; checked wire masks and shared predicate semantics. Negative: simple allocation-free bit tests align with session/filter consumers.
- `userspace-dp/src/tcp_flags_tests.rs` — TCP flag tests; checked constants and inline-consumer parity for SYN/ACK/close/local cases. Negative: prevents semantic drift between helpers and hot path.
- `userspace-dp/src/test_zone_ids.rs` — test constants; checked reserved-ID separation and fixture consistency. Negative: concrete IDs stay below Junos host/global sentinels.
- `userspace-dp/src/xsk_ffi.rs` — AF_XDP FFI; checked unsafe ownership, ring reserve/peek/submit/cancel, UMEM bounds, Send assumptions, drops, and integer conversions. Negative: callers own single-writer rings and guards bound frames/descriptors; no reachable out-of-bounds or double-release trace survived.
- `userspace-dp/src/xsk_ffi_tests.rs` — XSK FFI tests; checked frame bounds, ring transaction commit/cancel, descriptor access, and fake ownership. Negative: tests cover the principal unsafe wrapper contracts without finding source drift.
- `userspace-dp/src/fairness_eval/args.rs` — fairness CLI; checked missing/overflow/zero/nonfinite arguments and false-pass defaults. Negative: required numeric values fail fast; saturation requires a nonzero shaper rate.
- `userspace-dp/src/fairness_eval/inputs.rs` — fairness input parser; checked JSON/TSV bounds, malformed rows, interface filtering, and totals. Negative: malformed or absent required observations return errors rather than zero-data passes.
- `userspace-dp/src/fairness_eval/mod.rs` — fairness orchestration; checked phase order, error exits, and report/verdict coupling. Negative: analysis tool remains outside forwarding and propagates parse/verdict failures.
- `userspace-dp/src/fairness_eval/per_worker.rs` — per-worker aggregation; checked worker index bounds, zero workers, saturating totals, and allocation scale. Negative: bounded by configured workers and rejects impossible indexing.
- `userspace-dp/src/fairness_eval/per_worker_tests.rs` — aggregation tests; checked missing/skewed/balanced worker rows and filters. Negative: false-pass empty/skewed cases are represented.
- `userspace-dp/src/fairness_eval/report.rs` — report rendering; checked stable fields, finite values, and verdict parity. Negative: presentation does not alter gate decisions.
- `userspace-dp/src/fairness_eval/rss.rs` — RSS expectations; checked parser forms, active-worker/share bounds, and unknown expressions. Negative: malformed expectations error instead of silently selecting `any`.
- `userspace-dp/src/fairness_eval/verdict.rs` — fairness verdict; checked structural cap, saturation gate, CoV bounds, legacy mode, and Na/Nv scaling. Negative: the documented legacy no-interface behavior is explicit; no unreported false pass found.
- `userspace-dp/src/fairness_eval/windowing.rs` — window extraction; checked timestamp arithmetic, warmup/final burst, missing intervals, and finite throughput. Negative: invalid/empty windows fail rather than manufacture observations.
- `userspace-dp/src/filter/compiler.rs` — firewall-filter compiler; checked malformed protocol/address/port/DSCP/ICMP/flex fields, missing filter refs, input/output/lo0 bindings, policers, terminal conflicts, and cache sensitivity. Negative/new-finding result: dangling policers on tolerant load remain warning/no-op behavior already rooted in #2217; no new compiler bypass. Finding A1-b4-01 arises in the caller's skipped full preflight, not this compiler.
- `userspace-dp/src/filter/mod.rs` — filter types/state; checked default action, cache metadata, counters, policer handles, and status. Negative: default Accept is confined to no-match semantics; malformed security hooks are rejected by compiler preflight when it runs.
- `userspace-dp/src/filter/policer.rs` — policer implementation; checked token arithmetic, refill caps, concurrent atomics, color modes, and invalid config fallback. Negative: fail-closed runtimes and saturating arithmetic prevent overflow-driven admission.
- `userspace-dp/src/filter/tests.rs` — filter tests; checked ingress/egress/lo0, terminal/fall-through, counters/logging, addresses/ports/exceptions, protocols, fragments, DSCP/flex/TCP/ICMP, policers, cache replay, and malformed snapshots. Negative: broad hostile coverage; no test covers an initial `defer_workers=true` handler bypass of this compiler.
- `userspace-dp/src/filter/engine/cache_sensitive.rs` — filter cache compatibility; checked semantic equality, per-packet predicates, policer identity, and refresh invalidation. Negative: changed cache-sensitive semantics prevent stale reuse; bounded comparisons stay off the per-packet common path.
- `userspace-dp/src/filter/engine/eval.rs` — filter evaluator; checked term order, continue terms, counters/logging, routing-instance split, default Accept, and terminal normalization. Negative: terminal discard/reject survives modifiers and fall-through state; no false permit/drop found.
- `userspace-dp/src/filter/engine/matching.rs` — term matching; checked family, constrained-empty/except, protocol/port, fragments, DSCP/TCP/ICMP/flex bounds, and missing L4. Negative: absent required packet bytes fail term matching closed.
- `userspace-dp/src/filter/engine/mod.rs` — engine exports; checked module visibility and single implementation routing. Negative: no alternate evaluator bypass exposed.
- `userspace-dp/src/filter/engine/policer.rs` — policer application; checked missing runtime behavior, drop propagation, cached replay, and once-per-packet semantics. Negative: valid handles meter consistently; dangling tolerant references are prior-root duplicate evidence.
- `userspace-dp/src/filter/engine/tx_selection.rs` — TX filter leg; checked egress action, modifiers, output filter, policer, route/CoS order, and counters. Negative: output terminal decisions are not lost behind TX-selection modifiers.
- `userspace-dp/src/protocol/binding.rs` — binding DTOs; checked serde defaults, queue/ifindex widths, readiness flags, counters, VLAN/RETH identity carriage, and compatibility. Negative: additive defaults do not themselves widen a policy verdict; runtime readiness gates remain elsewhere.
- `userspace-dp/src/protocol/control.rs` — control DTOs; checked request/response optional fields, defaults, limits, and HA/session verbs. Negative: missing payloads are rejected by handlers; no request default invokes a mutating permit path.
- `userspace-dp/src/protocol/cos.rs` — CoS DTOs; checked numeric widths, queue identity, defaults, status, and compatibility. Negative: no policy action encoded here and bounds are validated in forwarding build.
- `userspace-dp/src/protocol/mod.rs` — protocol root; checked null-tolerant vectors, module exports, version shape, and serde helpers. Negative: null compatibility is explicit and consumers retain integrity checks.
- `userspace-dp/src/protocol/nat.rs` — NAT DTOs; checked source/static/destination NAT scope, ports, zones, route/PBR ordering fields, and skew defaults. Negative: known additive compatibility fields preserve older snapshots; enforcement parsers own fail-closed validation.
- `userspace-dp/src/protocol/resolution.rs` — neighbor/resolution DTOs; checked family, ifindex/VLAN, MAC parsing inputs, and defaults. Negative: malformed resolution state cannot directly select policy permit.
- `userspace-dp/src/protocol/security.rs` — security DTOs; checked policy/global/Junos-host/app fields, filter constraints, screen missing refs, counters, fragments, and compatibility defaults. Negative/new-finding result: missing-screen Pass behavior is explicitly prior-root #3082 deferred policy and duplicate evidence, not a new finding.
- `userspace-dp/src/protocol/snapshot.rs` — snapshot DTO; checked protocol version, zones/interfaces/RETH/VLAN, generations, map pins, filters/screens/NAT/routing fields, and old-helper defaults. Negative: DTO defaults require downstream preflight; Finding A1-b4-01 is the handler branch that skips it.
- `userspace-dp/src/protocol/tests.rs` — wire tests; checked JSON round trips, defaults/nulls, version fixture, additive fields, and cross-language shapes. Negative: compatibility fields are pinned without hiding malformed semantic validation.
- `userspace-dp/src/screen/extract.rs` — packet extraction; checked IPv4 IHL/length/options, IPv6 extension bounds, fragments, L4 availability, and source-route signals. Negative: checked offsets and explicit parse errors prevent payload-as-header reads.
- `userspace-dp/src/screen/mod.rs` — screen orchestration; checked missing profiles, stateless/rate order, flowless/control traffic, fabric skip, alarm-without-drop, cookies, scan/session limits, and counters. Negative: configured checks enforce both v4/v6 paths; missing-profile Pass is known #3082 duplicate behavior.
- `userspace-dp/src/screen/packet.rs` — screen packet/profile types; checked field widths, parse error mapping, and verdict variants. Negative: type layer preserves explicit Drop/Challenge/Bypass distinctions.
- `userspace-dp/src/screen/rate.rs` — rate counters; checked window rollover, fixed-point refill, multiplication bounds, cold-start burst, and time regression. Negative: capped elapsed/refill and saturating math avoid overflow admission.
- `userspace-dp/src/screen/rate_tests.rs` — rate tests; checked threshold edges, bursts, idle refill, rollback, and overflow. Negative: both over-drop and under-drop boundaries are exercised.
- `userspace-dp/src/screen/scan.rs` — scan/sweep tracker; checked cardinality caps, eviction, cleanup budgets, time windows, zone isolation, and pressure behavior. Negative: bounded tables retain a fail-closed observation under saturation and expose pressure.
- `userspace-dp/src/screen/stateless.rs` — stateless checks; checked LAND, TCP flags, ping-death, teardrop, fragments, and source route for v4/v6. Negative: predicates use parsed lengths/flags and do not allocate or lock.
- `userspace-dp/src/screen/syn_rate.rs` — SYN sketches; checked hash seeding, per-source/destination keys, bounded cells, rate epochs, and collision behavior. Negative: fixed memory and conservative collisions avoid fail-open exhaustion.
- `userspace-dp/src/screen/syn_rate_tests.rs` — SYN-rate tests; checked threshold, epoch reset, source/destination/port isolation, and saturation. Negative: positive/negative boundaries pin conservative behavior.
- `userspace-dp/src/screen/syncookie.rs` — SYN cookies; checked epoch wrap, MAC domains, tuple/zone binding, MSS encoding, replay cache, capacity, and constant-time-ish hot operations. Negative: bounded cache and current/adjacent epoch validation reject forged/stale cookies.
- `userspace-dp/src/screen/tests.rs` — screen tests; checked stateless/rate/flowless/fabric/alarm/cookie/scan/limits, v4/v6, malformed packets, counters, and HA-ish key/profile transitions. Negative: extensive hostile cases; missing-profile Pass is intentionally pinned prior behavior.
- `userspace-dp/src/server/handlers/binding.rs` — binding handler; checked payload presence, slot validation, reconcile/status effects, and persistence. Negative: malformed requests fail without arbitrary slot mutation.
- `userspace-dp/src/server/handlers/export.rs` — export handler; checked optional request defaults, bounded export kickoff, off-lock wait handoff, and status. Negative: bulk work is moved outside the global lock.
- `userspace-dp/src/server/handlers/forwarding.rs` — forwarding handler; checked armed-state transition, reconcile invocation, and status. Negative: no direct policy state mutation or silent success on missing payload.
- `userspace-dp/src/server/handlers/ha.rs` — HA handler; checked role payload, demotion/promotion handoff, and state updates. Negative: handler delegates session/worker invariants and rejects absent state.
- `userspace-dp/src/server/handlers/inject_packet.rs` — injection handler; checked packet payload presence, size/decode handling, and queue error propagation. Negative: no arbitrary source read or unbounded packet allocation found.
- `userspace-dp/src/server/handlers/mod.rs` — control dispatcher; checked 5-second I/O timeouts, 16 MiB cap, decode-before-lock, lock scope, response defaults, persistence trigger, and every verb dispatch. Negative: malformed/oversize input fails before mutation; Finding A1-b4-01's `ok=true` comes from the snapshot handler branch.
- `userspace-dp/src/server/handlers/neighbors.rs` — neighbor handler; checked payload/default replace semantics, refresh, and persistence. Negative: updates are typed and do not alter policy admission.
- `userspace-dp/src/server/handlers/queue.rs` — queue handler; checked slot/queue payloads, replan/reconcile, and status. Negative: invalid queue state is rejected or bounded by helper validation.
- `userspace-dp/src/server/handlers/rebind.rs` — rebind handler; checked target selection, stop/reconcile sequence, and errors. Negative: no concurrent double-bind path found at handler scope.
- `userspace-dp/src/server/handlers/session_deltas.rs` — delta handler; checked default/max conversion, bounded draining, and empty behavior. Negative: minimum one and downstream bounded drain prevent unbounded response construction.
- `userspace-dp/src/server/handlers/snapshot.rs` — snapshot publication; checked version/policy/full-build preflights, same/full plan atomicity, generations, deferred workers, FIB bumps, rollback, persistence, and old-state restoration. Finding A1-b4-01: initial deferred apply skips the complete forwarding integrity build yet persists/acknowledges the snapshot.
- `userspace-dp/src/server/handlers/stop_workers.rs` — stop handler; checked worker teardown, status reset, and idempotence. Negative: no session/policy permit side effect.
- `userspace-dp/src/server/handlers/sync_session.rs` — HA session handler; checked payload presence, queueing, errors, and status. Negative: typed sync request delegates collision/ownership checks to session install.
- `userspace-dp/src/server/helpers.rs` — server helpers; checked status aggregation, plan keys, canonical hash, interface/RETH binding identity, reconcile result propagation, queue planning, and locks. Negative: full reconcile errors propagate correctly when called; `same_plan_apply_needs_binding_reconcile` deliberately returns false for next-deferred snapshots, confirming Finding A1-b4-01.
- `userspace-dp/src/server/lifecycle.rs` — lifecycle; checked socket cleanup type checks, startup/shutdown threads, buffer sysctls, state load, and resource lifetime. Negative: stale cleanup does not unlink non-sockets; no silent daemon-ready state on bind failure.
- `userspace-dp/src/server/mod.rs` — server module root; checked exports and ownership. Negative: one handler/lifecycle implementation, no alternate snapshot path.
- `userspace-dp/src/server/state.rs` — server state; checked shared lock ownership and component grouping. Negative: state fields mutated under the server mutex.
- `userspace-dp/src/server/tests.rs` — server tests; checked malformed requests, snapshot policy/full/same-plan failure atomicity, bindings, status, HA/export, and lifecycle. Negative/gap: tests cover a later non-deferred reconcile failure restoring a valid deferred snapshot, but not an invalid initial `defer_workers=true` apply; this supports Finding A1-b4-01.
- `userspace-dp/src/session/ctx.rs` — session update contexts; checked typed parameter grouping and HA replacement flags. Negative: contexts reduce positional mixups without defaulting policy identity to permit.
- `userspace-dp/src/session/entry.rs` — session records; checked zone/policy/app IDs, counters, NAT metadata, timeouts, origins, equality, and HA wire deltas. Negative: policy metadata is immutable/bound as documented and equality excludes only derived counter handles.
- `userspace-dp/src/session/expire.rs` — expiry; checked wheel generations, stale handles, TCP/app/zone timeout selection, NAT allocation release, counters, and bounded budgets. Negative: stale wheel entries validate handles/epochs before removal and resources release at removal sinks.
- `userspace-dp/src/session/install.rs` — installation; checked capacity preflight, replacement collision guards, forward/reverse groups, HA import, counters, policy metadata, and partial-install telemetry. Negative: at-cap and post-preflight failures do not silently install a partial admitted flow without accounting.
- `userspace-dp/src/session/key.rs` — session keys; checked v4/v6 representation, protocol/ports, reverse/NAT derivation, hashing, byte order, and HA stability. Negative: typed full tuples avoid cross-family aliasing.
- `userspace-dp/src/session/lookup.rs` — lookup; checked canonical/alias/NAT/wire indices, collision buckets, validation, TCP transitions, expiry refresh, and owner-RG take. Negative: every candidate is revalidated against the full tuple before returning.
- `userspace-dp/src/session/mod.rs` — session coordinator; checked slab/index ownership, seeded maps, policy counter binding, update/reindex, HA transition, generation handles, limits, and removals. Negative: secondary indices are reasserted on in-place refresh and stale handles fail safely; no policy generation bypass isolated in assigned code.
- `userspace-dp/src/session/tests.rs` — session tests; checked install/lookup/expiry, collisions, NAT/wire aliases, HA sync/promotion, policy/app metadata, limits, counters, and stale handles. Negative: hostile collision and lifecycle coverage is extensive.
- `userspace-dp/src/session/wheel.rs` — expiry wheel; checked slot math, epoch tagging, bounded queues, and time wrap. Negative: stale entries require generation validation by the table before deletion.
- `userspace-dp/tests/cos_doc_drift.rs` — CoS doc guard; checked documented constants/paths against source. Negative: drift guard has no runtime policy effect and uses bounded file reads.
- `userspace-dp/tests/fairness_eval_blackbox.rs` — fairness black-box tests; checked CLI exits, malformed files/args, balanced/skewed gates, RSS, saturation, and report. Negative: catches zero-data and operator-error false passes.
- `userspace-dp/tests/snat_contract_doc_guard.rs` — SNAT doc guard; checked allocator/ordering contract text against implementation anchors. Negative: no runtime behavior, but protects documented NAT ordering invariants.
- `userspace-xdp/src/lib.rs` — XDP steering shim; checked strict/compat disabled behavior, binding/heartbeat failures, local/control exemptions, sessions, DNAT/interface NAT, native GRE, IPv4/IPv6/VLAN parsing, metadata lengths, redirect errors, and unsafe bounds. Negative: transit failures drop in strict userspace mode while explicit local/control traffic passes; no policy-evaluation bypass found in assigned shim logic.


## A2-b1


- `userspace-dp/src/nat/allocator.rs` - Source-NAT allocator and HA reservation state. Reviewed bitmap claims, address selection, PAT and deterministic v4/v6 mapping, persistent lease indexes/GC, rollback/release, address-only reverse ownership, synchronized reservation, caps, atomics, mutex scopes, integer bounds, and status snapshots. `A2-b1-F001` applies: deterministic address-only translation skips the reverse-identity owner used by the ordinary address-only path. Prior deterministic recycle, multi-address false-exhaustion, and HA address-only findings were deduplicated. The remaining PAT/persistent/GC paths had substantive negative results: bounded maps and chunked GC, exact-cap checks, no unsafe memory, and no unbounded packet allocation.
- `userspace-dp/src/nat/destination.rs` - DNAT exact host, wildcard port/protocol, prefix LPM, exemptions, source/application/scope constraints, local-address registration, and counters. `A2-b1-F002` applies: a malformed non-empty additive prefix silently becomes an exact-host entry and does not increment parse-error telemetry. Normal host/prefix lookup is immutable and allocation-free on packet lookup; zone-specific, interface/VRF, source, port, ICMP, and off constraints fail closed in the reviewed paths.
- `userspace-dp/src/nat/mod.rs` - Public NAT contract, `NatDecision` merge/reverse, stable counter registry, parse-error telemetry, and re-exports. Verified DNAT then SNAT merge keeps both tuple legs and HA serialization fields remain copy-only. Counter clear uses serialized registry traversal plus atomic subtraction; no new counter root beyond prior collision/history findings.
- `userspace-dp/src/nat/source.rs` - Snapshot parsing, strict match axes, off/interface/pool decisions, deterministic and address-only dispatch, failure tri-state, HA reserve/release, and DNAT-adjusted flow keys. `A2-b1-F001` is rooted here. Zone/interface/VRF/application/address constraints are ANDed; wrong-family, malformed constrained sets, allocator exhaustion, and non-first fragments return unavailable/no-match without widening. Source NAT executes only after policy and route/egress selection through the inspected callers.
- `userspace-dp/src/nat/static_nat.rs` - Bidirectional host/block mapping, source/port constraints, zone/interface/VRF precedence, counters, and external-address registration. Exact and block offset math, family checks, and scoped selection had no new finding. Malformed mapped-port and scope-order roots match prior reports and were not duplicated.
- `userspace-dp/src/nat/status.rs` - Pool status projection. Read-only linear aggregation of allocator snapshots; no packet-path work, lock inversion, arithmetic wrap, or API/show divergence found in the assigned surface.
- `userspace-dp/src/nat/tests_counter.rs` - Counter ID stability, shared counters, clear concurrency, and zero sentinel. All five assigned tests passed; meaningful negative result: clear/add interleaving is pinned, but this suite does not cover DNAT malformed-prefix telemetry (`A2-b1-F002`).
- `userspace-dp/src/nat/tests_destination.rs` - DNAT host/prefix, protocol/port, source, zone, off, scope, local registration, ordering, parse telemetry, and merge tests. All assigned tests passed. The parse-error test covers malformed destination and pool addresses but omits a non-empty malformed `destination_prefix` paired with a valid base address, the exact `A2-b1-F002` branch.
- `userspace-dp/src/nat/tests_dnat_proto.rs` - GRE/ICMPv6/IP-only, protocol-zero, resolver, specificity, and invalid-address cases. All assigned tests passed; protocol 0 is distinct from wildcard 256 and unknown destinations install nothing. No new finding.
- `userspace-dp/src/nat/tests_l4_match.rs` - SNAT/DNAT application protocol, source/destination ranges, ICMP type/code, impossible sentinels, off constraints, and unknown tuples. All assigned tests passed; malformed or missing L4 context narrows rather than widens admission. No new finding.
- `userspace-dp/src/nat/tests_pool.rs` - PAT, ICMP identifiers, port-less/address-only ownership, exhaustion, persistent leases, deterministic mapping, HA reserve, rollback/release, contention, GC, status, and fragments. All assigned tests passed. The suite separately proves deterministic block mapping and ordinary no-translation collision denial, but has no deterministic-plus-no-translation test; this omission permits `A2-b1-F001`.
- `userspace-dp/src/nat/tests_scope.rs` - Source, destination, and static NAT zone/interface/VRF/source constraints and coexistence. All assigned tests passed. Logical identity reaches these matchers through config-name and routing-instance maps; no new VLAN/RETH scope bug was found in assigned code.
- `userspace-dp/src/nat/tests_source.rs` - Interface SNAT, off ordering, reverse decision, bare hosts, malformed constrained sets, mixed valid/malformed parsing, and parse telemetry. All assigned tests passed; strict and lenient malformed-address behavior remains fail closed. No new finding beyond `A2-b1-F001`'s untested mode composition.
- `userspace-dp/src/nat/tests_static.rs` - Host/block v4/v6 mapping, offsets, zones, ports, coexistence, malformed input, and external IPs. All assigned tests passed. Existing malformed-port and scope findings were deduplicated; no new issue survived.
- `userspace-dp/src/nat64.rs` - `/96` parsing, tri-state classification, source/BIB allocation, deterministic v6, HA reservation/release, bounded fragment association, v4/v6 writers, extension headers, ICMP errors, checksums, lengths, DF/ID, and generated frames. All 121 NAT64 tests passed. Forward order is prefix classification and IPv4 route/zone lookup, mixed-family post-DNAT policy, then source allocation only on permit; unavailable pools drop before synthetic IPv6 routing. Non-first TCP/UDP fragments require a bounded first-fragment association; ICMP fragments fail closed. Prior prefix-grammar, association-commit, and HA roots were deduplicated; no new finding.
- `userspace-dp/src/nptv6.rs` - Prefix parse, overlap rejection, checksum-neutral adjustment, inbound destination and outbound source translation. All 28 NPTv6 tests passed. Inbound translation precedes route/zone/policy; outbound source translation follows policy and preempts ordinary SNAT. Prior discarded rule-set scope is a known campaign root and was not duplicated.

Cross-owner ordering trace/handoff: `afxdp/poll_descriptor/mod.rs` applies DNAT/static DNAT first, then inbound NPTv6, then NAT64 classification; it routes on the translated destination and evaluates zone policy against the post-destination-NAT tuple. Permit then allocates NAT64/SNAT or applies outbound NPTv6, composes the final `NatDecision`, installs forward/reverse session tuples, and only then reaches TX rewrite/output handling. Deny/reject exits precede source allocation; pool-unavailable and non-first-fragment failures drop. Missing-neighbor seeding repeats the same source-NAT composition. HA imports reserve PAT/NAT64 translated ports and teardown releases them; the already-known absence of HA address-only reservation was not re-reported. Packet-loop owners should add end-to-end regressions for both findings, including reverse tuple demux and malformed-prefix snapshot apply behavior; no separate cross-owner finding is duplicated here.


## A3-b1


- `pkg/appid/catalog.go` - Reviewed ID bounds, deterministic ordering, protocol resolution, omitted/explicit protocol 0, malformed and reversed ports, port-zero sentinel handling, ICMP type/code suppression, nil apps, and AppNames emission. Compiler and Rust parity tests pass. The `0-N` tolerant-load narrowing differs from policy rejection, but it is the already-indexed port-zero root (`git:6d4ff4442`) and was suppressed rather than re-filed.
- `pkg/appid/catalog_bad_protocol_4887_test.go` - Confirms an unrepresentable explicit protocol emits neither catalog rows nor a resolvable name while explicit protocol 0 remains valid. No new gap found.
- `pkg/appid/catalog_icmp_3781_test.go` - Confirms type/code-constrained ICMP does not acquire an over-broad L3/L4 catalog row or tuple-fallback label. Deferred type-aware identification is explicit; no verdict widening found.
- `pkg/appid/catalog_nil_app_4865_test.go` - Confirms nil user-application values do not panic catalog build or disabled-mode resolution. No resource or fail-open issue found in the assigned path.
- `pkg/appid/catalog_nil_appset_5179_test.go` - Confirms nil application-set values produce deterministic expansion failure instead of panic. Existing root `git:4d63e9ac3`; no new symptom.
- `pkg/appid/catalog_port_zero_5194_test.go` - Covers bare destination/source zero suppression and `0-N` normalization. The policy compiler rejects `0-N` while the label catalog narrows it, but this is the same prior port-zero normalization root (`git:6d4ff4442`), not a new finding.
- `pkg/appid/catalog_proto0_4008_test.go` - Confirms omitted protocol fan-out is distinct from explicit IANA protocol 0. Strict commit rejects referenced omitted-protocol apps; tolerant-path enforcement risk is already tracked under the protocol-less application root, so no duplicate was filed.
- `pkg/appid/catalog_tolerant_3725_test.go` - Confirms malformed source ports, reversed ranges, and dangling names fail closed for labeling. No new bounds or panic issue found.
- `pkg/appid/precedence_parity_test.go` - Shared fixture pins enabled Rust catalog precedence to disabled Go fallback precedence for forward tuples. Targeted Rust fixture passed; reverse lookup is covered on the Rust side and does not alter policy verdicts.
- `pkg/appid/protocol_lenient_3439_test.go` - Confirms display/filter names and numeric protocol tokens round-trip through the lenient resolver. No accepted-but-never-matches case found.
- `pkg/appid/protocol_number_2124_test.go` - Confirms named/numeric resolution, protocol 0, display round-trip, firewall-filter resolver parity, and port-bearing classification. No policy/application protocol SSOT drift found.
- `pkg/appid/runtime.go` - Reviewed policy/global/NAT reference collection, set expansion, nil slots, include-all behavior, AppID enabled/disabled resolution, deterministic specificity, canonical ports, and filter matching. No unintended permit/deny behavior is performed here; malformed labeling paths fail closed or map to `UNKNOWN`.
- `pkg/appid/runtime_test.go` - Covers policy and NAT catalog references, strict-validation set parity, enabled/disabled names, source ports, malformed ports, nonzero skew, overflow, and nil policy slots. No missing admission/denial assertion found in this unit scope.
- `pkg/appid/textrender.go` - Reviewed operator claims against catalog and fallback behavior. The text accurately disclaims L7 DPI and dynamic-application/AppFW support; no policy-verdict claim or vSRX completeness overstatement requiring a finding was identified.
- `pkg/appid/textrender_test.go` - Pins enabled/disabled disclosure, user-defined fallback ordering, and nil-config output. No security-sensitive omission found.
- `pkg/cmdtree/completion_nil_3476_test.go` - Confirms policy completion skips nil zone-pair and policy slots. No panic or stale candidate found.
- `pkg/cmdtree/completion_nil_3493_test.go` - Confirms packet-drop zone completion skips nil zone values. No new nil-provider issue found.
- `pkg/cmdtree/completion_nil_provider_5196_test.go` - Confirms nil-config providers still return config-independent route tables/protocols in both completion APIs. No new boot/recovery issue found.
- `pkg/cmdtree/completion_nil_ri_rg_4866_test.go` - Confirms routing-instance/table and redundancy-group providers skip nil entries. No HA mutation or execution path is present.
- `pkg/cmdtree/completion_zone_prefix_5196_test.go` - Confirms canonicalized unique prefixes preserve zone context for policy-name completion. It does not cover typed `test policy` selector values; see the finding below.
- `pkg/cmdtree/tree.go` - Reviewed operational/config roots, dynamic providers, placeholders, typed leaves, unique-prefix traversal, descriptions, and nil behavior. Found that the `test policy` tree cannot traverse selector values and exposes only a rigid subset/order despite the strict parser accepting a repeatable selector grammar.
- `pkg/cmdtree/tree_hb167_test.go` - Confirms requested vSRX drill-down nodes exist. Presence-only coverage does not validate dispatcher grammar, but no mismatch was found for these four leaves.
- `pkg/cmdtree/tree_test.go` - Covers placeholders, dynamic values, unique prefixes, descriptions, DDNS, CoS, interface queues, and configured names. It lacks a parser-versus-tree contract test for policy simulator selectors, allowing the finding below.


## A3-b2


### AST, address books, groups, and formatting

- `pkg/config/addressbook_dup_addrset_merge_4706_test.go` - duplicate address-set blocks union and deduplicate direct/nested members; deny-set member retention is covered; no residual overwrite found.
- `pkg/config/addressbook_name_slash_3061_test.go` - reserved-prefix and zone-name slash rejection plus lenient warning paths; no ordinary address condition loss found.
- `pkg/config/addressbook_name_slash_4340_test.go` - legal slash-bearing names and zone-local folding round-trip; no false rejection found.
- `pkg/config/addressset_bracket_members_4791_test.go` - bracket direct/nested member retention and singleton control; all address operands survive compilation.
- `pkg/config/allow_dataplane_sleep_test.go` - inert userspace knob parsing/schema/advisory only; no policy mutation.
- `pkg/config/application_set_nested_test.go` - flat/hierarchical/deep/cyclic app-set expansion; bounded recursion and cycle error preserve fail-closed behavior.
- `pkg/config/applicationset_bracket_members_5181_test.go` - flat/hierarchical/nested bracket members and deny-policy coverage; all listed applications survive.
- `pkg/config/apply_groups_depth_5194_test.go` - depth cap and valid shallow expansion; recursion is bounded before stack/resource failure.
- `pkg/config/apply_groups_leaflist_exclude_test.go` - range/operation token leaves override while protocol leaf-lists union; no token-mashing regression found.
- `pkg/config/apply_groups_leaflist_test.go` - all block/collapsed combinations, policy applications/addresses, scalar precedence, and sibling containers; configured list conditions are retained.
- `pkg/config/apply_groups_transitive_4474_test.go` - transitive chains, cycles, diamond memoization, tags, and own content; bounded and deterministic.
- `pkg/config/archival_leading_dash_4589_test.go` - archive-site command-option injection rejection; unrelated to forwarding conditions.
- `pkg/config/ast.go` - node identity, cloning, navigation, union, annotation, and insertion primitives reviewed; clone/path matching preserve children and inactive metadata.
- `pkg/config/ast_edit.go` - copy/rename/order/set/delete/activate/deactivate paths reviewed, including multi-leaf members; no assigned policy/filter/NAT member truncation found.
- `pkg/config/ast_format.go` - canonical, set, diff, JSON, and XML rendering reviewed; quoted keys and inactive state remain represented.
- `pkg/config/ast_groups.go` - group lookup, context memoization, wildcard merge, typed leaf-list union, depth/work caps reviewed; no new condition loss beyond the finding below in the downstream application compiler.
- `pkg/config/ast_redact.go` - clone-only secret masking and placeholder ingestion guard; no mutation of compiled source tree.
- `pkg/config/ast_redact_test.go` - secret coverage across formats, source immutability, placeholder rejection, and qualifier preservation; substantive negative coverage.

### Core dispatch, routing-adjacent, chassis, CoS, and DDNS

- `pkg/config/backup_router_family_2911_test.go` - v4/v6 next-hop/destination family parity and lenient warning; no route-condition widening.
- `pkg/config/backup_router_format_4808_test.go` - malformed next hop/destination strict and lenient matrix; invalid values do not silently become defaults.
- `pkg/config/bgp_as_wrap_4713_test.go` - signed/oversized ASN values remain inert leniently and reject strictly; no integer wrap.
- `pkg/config/bgp_group_inherit_order_5270_test.go` - group inheritance is order-independent and neighbor override wins; no chain loss.
- `pkg/config/bgp_neighbor_peeras_2963_test.go` - missing/inherited/per-neighbor peer-AS strict/lenient handling; no silent zero-AS use.
- `pkg/config/bgp_peeras_range_4589_test.go` - ASN boundaries reject/accept correctly.
- `pkg/config/bgp_policy_chain_level_5277_test.go` - neighbor import/export replacement and group inheritance retain complete policy chains.
- `pkg/config/compile_golden_4406_test.go` - broad golden typed-output regression; useful positive coverage, but does not exercise conflicting direct application leaves.
- `pkg/config/compiler.go` - strict/lenient and per-node orchestration, clone/prune/group expansion, default initialization, gates, derivations, and dispatch reviewed; default policy initializes deny and no later stage flips ordinary actions.
- `pkg/config/compiler_as_path_prepend_2892_test.go` - prepend token preservation and validation; unrelated to packet policy admission.
- `pkg/config/compiler_bgp_as_3870_test.go` - BGP AS parsing boundaries; no wrap/default drift.
- `pkg/config/compiler_chassis.go` - device-map collection/normalization and duplicate validation reviewed; bounded cold-path maps.
- `pkg/config/compiler_chassis_device_map_test.go` - device-map identities/properties and conflicts covered; no forwarding policy coupling.
- `pkg/config/compiler_class_of_service.go` - classifier/scheduler/rewrite/rate parsing and interface inheritance reviewed; no security action rewrite, bounded cold-path work.
- `pkg/config/compiler_cluster_authkey_4107_test.go` - cluster key strict handling; no policy coupling.
- `pkg/config/compiler_cos_fc_queue_4594_test.go` - forwarding-class queue mapping boundaries; no filter verdict mutation.
- `pkg/config/compiler_cos_rate_percent_strict_4320_test.go` - percentage rates strict/lenient behavior; no numeric overflow found.
- `pkg/config/compiler_cos_tcp_hb167_test.go` - three-color policer parsing parity; no new fail-open root in assigned layer.
- `pkg/config/compiler_ddns_duration_4837_test.go` - duration bounds; no forwarding effect.
- `pkg/config/compiler_ddns_tls.go` - credential-bearing endpoint detection and URL userinfo parsing reviewed; no compiler action coupling.
- `pkg/config/compiler_ddns_tls_4861_test.go` - plaintext/TLS credential endpoint matrix; no policy effect.
- `pkg/config/compiler_derivations.go` - derived config ordering and normalizations reviewed; application/security actions are not rewritten here.
- `pkg/config/compiler_dhcp_ddns_test.go` - DHCP/DDNS typed retention and validation; no filter/NAT action coupling.
- `pkg/config/compiler_dhcp_relay_overrides_test.go` - relay overrides and inheritance; no security condition mutation.
- `pkg/config/compiler_dispatch.go` - section fan-out reviewed; all repeated top-level application/firewall/security sections are dispatched, with collision gates handling named duplicates.
- `pkg/config/compiler_earlystrict.go` - early strict folds/gates reviewed; no warning-to-permit conversion found.
- `pkg/config/compiler_equal_flow_target_policy_test.go` - equal-flow policy target parsing; no security policy interaction.
- `pkg/config/compiler_equal_flow_worker_cap_test.go` - worker cap bounds; resource safety covered.
- `pkg/config/compiler_f3_hb167_test.go` - feature parity regression; no assigned action drift.
- `pkg/config/compiler_frr_policy_inject_4097_test.go` - control-character rejection; no command injection.
- `pkg/config/compiler_inert_knobs_4306_test.go` - accepted-but-inert knobs are disclosed; no hidden enforcement claim.

### Applications and default policy

- `pkg/config/compiler_addrbook_warn_3958_test.go` - valid address reference forms avoid false warnings and undefined refs remain visible.
- `pkg/config/compiler_application_destport_names_3340_test.go` - named, mixed-case, range, source-port, and inline-term resolution plus unknown-name rejection; resolver parity is sound.
- `pkg/config/compiler_application_junos_ping_3348_test.go` - ping aliases, explicit type/code, malformed values, mixed all-ICMP, and cross-field rejects; ICMP constraints are retained.
- `pkg/config/compiler_application_mixed_term_3366_test.go` - mixed direct/term and conflicting scalar duplicates are covered only inside `term`; missing direct-body duplicate coverage supports F1.
- `pkg/config/compiler_application_port_range_zero_4336_test.go` - zero-floor port-range compatibility and surrounding guards; no accidental rejection.
- `pkg/config/compiler_application_set_member_3890_test.go` - typoed opaque members reject strictly/warn leniently; valid and description-only sets remain intact.
- `pkg/config/compiler_application_specs_test.go` - referenced protocol/port/ICMP validity, app-set reachability, AppID scope, and lenient warnings; does not test repeated direct scalar leaves.
- `pkg/config/compiler_application_term_alg_3352_3353_test.go` - opaque term syntax and ALG handling; unknown term leaves fail closed.
- `pkg/config/compiler_application_timeout_3320_test.go` - direct/term timeout parsing and malformed-value retention; single configured values survive.
- `pkg/config/compiler_applications.go` - direct and term application lowering, aliases, named ports, ranges, sets, syntax metadata reviewed; F1 is the surviving direct-scalar overwrite root.
- `pkg/config/compiler_applications_collision.go` - authored/generated app/set namespace collisions and duplicate generated names reviewed; it counts object identities, not duplicate leaves inside one object, so it does not refute F1.
- `pkg/config/compiler_applications_collision_3339_test.go` - duplicate objects/sets/generated names and split blocks covered; same-object scalar duplicates absent.
- `pkg/config/compiler_default_policy_3065_test.go` - absent default is deny; explicit permit/deny/reject map correctly; schema enum covered.
- `pkg/config/compiler_default_policy_log_3534_test.go` - default-policy logging modifiers and warnings retain the terminal default action.

### Firewall filters and interfaces

- `pkg/config/compiler_filter_action_test.go` - accept/discard/reject/next/log/count/action conflicts covered; no terminal inversion.
- `pkg/config/compiler_filter_loss_priority_2507_test.go` - inert loss-priority warning; no hidden enforcement.
- `pkg/config/compiler_filter_nocatchall_3295_test.go` - implicit filter default and no-catch-all advisories; default behavior remains explicit.
- `pkg/config/compiler_filter_protocol_test.go` - protocol token validation; unresolved protocol does not become wildcard on strict commit.
- `pkg/config/compiler_filter_ref_3296_test.go` - interface filter references strict/lenient matrix; dangling refs remain visible/fail-safe downstream.
- `pkg/config/compiler_firewall.go` - family expansion, term match accumulation, prefix lists, ports, protocol/ICMP/fragments/flex match, actions, and policers reviewed; all ordinary supported match leaves append rather than overwrite.
- `pkg/config/compiler_firewall_family_any_4287_test.go` - `family any` emits v4 and v6 arms; no IPv6 bypass.
- `pkg/config/compiler_firewall_family_any_match_4296_test.go` - family-specific matches under `any` reject/warn; family-agnostic matches remain valid.
- `pkg/config/compiler_firewall_family_any_prefixlist_4426_test.go` - positive/except single-family hazards reject strictly and are surfaced leniently; mixed-family controls covered.
- `pkg/config/compiler_firewall_family_bounds_4827_test.go` - malformed empty-key trees do not panic; valid controls remain functional.
- `pkg/config/compiler_firewall_family_collision_3884_test.go` - cross-family overwrite collisions reject, split-block and lenient cases covered.
- `pkg/config/compiler_flat_reth_nodeid_4329_test.go` - node-local RETH/fabric resolution and explicit override; logical interface identity retained.
- `pkg/config/compiler_interface_range.go` - flat/hierarchical member and range expansion, diagnostics, and overflow guards reviewed; bounded expansion.
- `pkg/config/compiler_interface_range_4027_test.go` - range precedence, multiple ranges, huge-end overflow, and termination covered.
- `pkg/config/compiler_interfaces.go` - physical/unit/family/address/filter/sampling/tunnel/VRRP/DDNS lowering reviewed; input/output filter refs and family remain distinct.
- `pkg/config/compiler_interfaces_unsupported.go` - unsupported MAC/ARP-policer/QinQ shapes detected after group expansion and inactive pruning.
- `pkg/config/compiler_interfaces_unsupported_test.go` - flat/hierarchical/lenient/inactive/apply-groups matrix and false-positive controls; no silent unsupported enforcement.
- `pkg/config/compiler_junos_host_direct_warn_4146_test.go` - direct host delivery policy gap advisories, enforced and nil-safe controls; no transit action mutation.
- `pkg/config/compiler_lo0_mirror_modifiers_3445_test.go` - kernel mirror modifier divergence is warned and honored controls avoid false positives.

### IPsec

- `pkg/config/compiler_ipsec.go` - IKE/IPsec proposals, gateways, DPD, VPN/manual fields and endpoint validation reviewed; no security-policy terminal action coupling.
- `pkg/config/compiler_ipsec_bindiface.go` - secure-tunnel bind-interface collision walk is all-sibling and strict/lenient aware.
- `pkg/config/compiler_ipsec_bindiface_2933_test.go` - ambiguous/unambiguous/lenient bind cases covered.
- `pkg/config/compiler_ipsec_bindiface_validate_5297_test.go` - invalid names, schema, lenient warning, and collision non-regression covered.
- `pkg/config/compiler_ipsec_gateway_ref_test.go` - gateway references and endpoint shape/length validation; no silent empty endpoint.
- `pkg/config/compiler_ipsec_hb167_parity_test.go` - proposal-set expansion, AH/manual rejection, monitor/advisories, and establish-tunnels enum; vSRX parity surfaced.
- `pkg/config/compiler_ipsec_proposals_multivalue_3904_test.go` - all flat/hierarchical proposal members and dangling second refs retained/rejected.
- `pkg/config/compiler_ipsec_proposalset.go` - immutable proposal catalogs, synthetic names, reserved-name guards, and expansion reviewed; bounded lists.
- `pkg/config/compiler_ipsec_reserved_proposal_name_5195_test.go` - strict collision rejection and lenient authored-crypto preservation; no overwrite.
- `pkg/config/compiler_ipsec_trafficselector.go` - traffic-selector token extraction, shape/whitespace/control validation reviewed.
- `pkg/config/compiler_ipsec_ts_4098_test.go` - malformed/control/whitespace/CIDR strict/lenient matrix and valid host/range controls.

### Destination/source NAT and NAT64

- `pkg/config/compiler_dnat_address_test.go` - destination address parsing/validation and multiple values; no wildcard collapse.
- `pkg/config/compiler_dnat_protocol_test.go` - DNAT protocol capture and invalid token rejection; no protocol widening.
- `pkg/config/compiler_dup_flow_subblock_3566_test.go` - duplicate nested strict-gate bypass regression coverage; all matching siblings walked.
- `pkg/config/compiler_dup_match_then_3850_test.go` - duplicate match blocks AND-accumulate and then blocks resolve explicitly; no first-block condition loss.
- `pkg/config/compiler_dup_policy_name_3473_test.go` - duplicate policy identity rejection across hierarchical blocks; no policy overwrite.
- `pkg/config/compiler_dup_security_3562_test.go` - duplicate top-level security-block gate coverage; no hidden invalid sibling.
- `pkg/config/compiler_dynamic_address_feed_ref_3300_test.go` - feed references strict/lenient paths; unresolved names remain visible.
- `pkg/config/compiler_feed_address_token_3294_test.go` - feed address token validation; malformed values do not become broad literals.
- `pkg/config/compiler_feed_url_malformed_5183_test.go` - malformed URL strict/lenient behavior; no policy content mutation.
- `pkg/config/compiler_nat64_extra_slash_5517_test.go` - extra-slash malformed prefixes reject/warn; valid `/96` preserved.
- `pkg/config/compiler_nat64_prefix_test.go` - `/96`, source pool, malformed/family/length, and lenient matrix; unsupported prefixes never compile silently.
- `pkg/config/compiler_nat_address_name_feed_3418_test.go` - direct feed references work on SNAT/DNAT source/destination axes.
- `pkg/config/compiler_nat_address_name_resolvable_3425_test.go` - empty/prefixless sets reject, direct/nonempty values accept, lenient warning covered.
- `pkg/config/compiler_nat_application_specs_test.go` - NAT-referenced app protocol/port validity and lenient behavior; shares application validation but lacks F1 shape.
- `pkg/config/compiler_nat_dest_address_name_3229_test.go` - DNAT/SNAT destination address-name retention and undefined strict/lenient behavior.
- `pkg/config/compiler_nat_destination.go` - pools, all `from` scopes, duplicate match accumulation, address/name/protocol/application/port fields, off/pool actions, and bounded range expansion reviewed; no new NAT widening found.
- `pkg/config/compiler_nat_dnat_off_3844_test.go` - `destination-nat off` remains an explicit exemption and stops fallthrough.
- `pkg/config/compiler_nat_dnat_pool_3450_test.go` - pool host/port validity, raw preservation, and address-port form covered.
- `pkg/config/compiler_nat_dnat_port_range_3449_test.go` - invalid huge ranges do not expand; valid range bounded to 65,535 members.
- `pkg/config/compiler_nat_dnat_to.go` - destination-NAT unsupported `to` walk descends all duplicate blocks; strict reject and lenient warning without typed phantom scope.
- `pkg/config/compiler_nat_dnat_to_3444_test.go` - strict/lenient and duplicate security/NAT/destination levels plus from-only control covered.
- `pkg/config/compiler_nat_dup_subblock_3915_test.go` - source/destination/static/NAT64/proxy-ARP duplicate blocks merge; singleton behavior unchanged.
- `pkg/config/compiler_nat_helpers.go` - family/host-mask, scope parsing/application, pool lists/ranges, and deterministic keys reviewed; empty scope defaults are deliberate global semantics and invalid constrained values retain metadata.
- `pkg/config/compiler_nat_host_mask_test.go` - static/NAT64 host masks, mapped-v6, block pairs, ports, malformed values, lenient warnings, and helper predicates comprehensively covered.
- `pkg/config/compiler_nat_match_application_3434_test.go` - undefined/empty app sets reject, defined accepts, lenient warns; no app criterion wildcarding at strict commit.
- `pkg/config/compiler_nat_match_dport_3446_test.go` - invalid source/destination ports reject and raw invalid tokens survive for fail-closed lowering.
- `pkg/config/compiler_nat_match_multivalue_3431_test.go` - all flat/hierarchical addresses/names/protocols/apps accumulate; bad second protocol rejected.
- `pkg/config/compiler_nat_dnat_to_3444_test.go` - duplicate-level bypass and from-only positive controls rechecked with the production walker; no residual scope loss.


## A3-b3


### Strict/lenient matrix

| Input class | Strict commit | Lenient load/HA | Typed/runtime consequence | Result |
|---|---|---|---|---|
| Complete policy, explicit permit/deny/reject | Accept | Accept | Action and all match dimensions retained | consistent |
| No terminal action | Reject | Warn | Compiler forces `PolicyDeny` | fail closed |
| Undefined address/application | Reject | Warn | Non-empty unresolved content becomes snapshot rejection sentinel | fail closed downstream |
| Undefined zone/scoped-global zone | Reject | Warn | Snapshot integrity rejects unknown zone and retains last good | fail closed downstream |
| Unsupported match leaf or missing required match leaf | Reject | Warn | Leaf/absence leaves no typed marker; empty dimensions lower as match-any | A3-b3-F1 |
| Unsupported `then permit` modifier | Reject | Warn | Modifier is dropped while permit remains | same quarantine root as A3-b3-F1 |
| Unknown host-inbound token | Reject | Warn | Existing compatibility behavior retained; kernel/Rust mismatch is signaled | no new root; historical #3200 compatibility caveat |
| Actionless/default policy | Default deny | Default deny | `PolicyDeny` initialized explicitly | consistent |

### Typed-to-compiled field ledger

| AST/config surface | Typed field | Compiled/runtime consumer | Inspection result |
|---|---|---|---|
| zone-pair scope | `ZonePairPolicies.FromZone/ToZone` | userspace policy tier and zone-ID resolver | preserved for flat/hierarchical forms; strict references checked |
| global scope | `PolicyMatch.FromZones/ToZones` | scoped-global set matcher | accumulated, sorted/deduped; any/junos-host direction rules checked |
| addresses/exclusions | `SourceAddresses`, `DestinationAddresses`, exclusion flags | address books/literals in policy snapshot | dual AST slots accumulated; undefined non-empty values reject downstream |
| applications/app sets | `PolicyMatch.Applications` | `expandUserspacePolicyApplications` | defined terms expand; empty means match-any; missing-leaf quarantine absent (F1) |
| terminal action | `Policy.Action`, `terminalActions` | permit/deny/reject snapshot action | duplicates conflict strictly; no-action lenient default is deny |
| logging/count | `Policy.Log`, `Policy.Count` | session flags/counters | duplicate and collapsed deny modifiers accumulated; deny/reject inert-log warnings present |
| default policy | `Security.DefaultPolicy` and log flags | no-match verdict | explicit deny default; permit/deny/reject parsed consistently |
| zones/interfaces | `Security.Zones`, interface membership/overrides | interface-zone IDs and host-inbound | duplicate blocks merged; bracket membership flattened; strict membership/definedness checked |
| NAT scope/match/action | typed source/static/NPTv6 rules | pre-policy DNAT/static and post-policy SNAT lowering | scope kinds, ports, address families, targets and ranges validated; no zone-policy bypass found |
| filters/screens/routing | typed filter, screen, route/PBR fields | userspace ordering contracts | strict representability and reference gates present; no assigned lowering inconsistency found |

### File ledger

- `pkg/config/compiler_nat_mixed_scope.go` — NAT grammar; scope-kind Cartesian expansion; mixed kinds strictly rejected and leniently warned; no new policy bypass.
- `pkg/config/compiler_nat_mixed_scope_4881_test.go` — NAT tests; strict/lenient source/destination/static scope matrix; substantive positive/negative coverage.
- `pkg/config/compiler_nat_persistent_permit_test.go` — NAT tests; persistent permit enum/default/schema; no zone-policy interaction defect.
- `pkg/config/compiler_nat_pool_alarm_test.go` — NAT tests; thresholds, inversion, lenient compatibility; bounds covered.
- `pkg/config/compiler_nat_reversed_port_range_4422_test.go` — NAT tests; reversed match/pool ranges fail strict; valid endpoints retained.
- `pkg/config/compiler_nat_scope_3079_test.go` — NAT tests; zone/interface/RI typed scope capture and lenient parity; no silent scope drop.
- `pkg/config/compiler_nat_source.go` — NAT compiler; source pools/rules/NAT64, port/address parsing and scope application; no new widening found.
- `pkg/config/compiler_nat_source_address_name_2416_test.go` — NAT tests; address-name references strict/lenient; unresolved names signaled.
- `pkg/config/compiler_nat_source_dport_3429_test.go` — NAT tests; scalar/range/bracket destination ports; all tokens retained.
- `pkg/config/compiler_nat_source_pool_address_4521_test.go` — NAT tests; discrete/range/bracket/hierarchical pool addresses; parity covered.
- `pkg/config/compiler_nat_source_pool_port_3906_test.go` — NAT tests; pool port range/no-translation validation; invalid values rejected.
- `pkg/config/compiler_nat_source_pool_port_5457_test.go` — NAT tests; parser fail-closed cases and valid boundaries; no integer widening.
- `pkg/config/compiler_nat_static.go` — static NAT compiler; prefix family/host checks, ports, RI and address-name resolution; no policy-order bypass found.
- `pkg/config/compiler_nat_target_parity_hb167_test.go` — NAT tests; static/DNAT/SNAT target resolution and advisories; unresolved targets covered.
- `pkg/config/compiler_nptv6_self_overlap_4339_test.go` — NPTv6 tests; self-versus-real overlap discrimination; no false overlap.
- `pkg/config/compiler_nptv6_test.go` — NPTv6 tests; family, host bits, lengths, overlap, strict/lenient matrix; comprehensive negatives.
- `pkg/config/compiler_p3_http_providers_test.go` — DDNS tests; provider parsing and malformed URL/allowlist warnings; unrelated to policy admission.
- `pkg/config/compiler_policy_dup_block_3842_test.go` — policy tests; duplicate match accumulation and terminal conflicts; strict bypass regression covered.
- `pkg/config/compiler_policy_global_zone_3148_test.go` — policy tests; global/scoped-global/any/junos-host/undefined-zone matrix; no tier drift found.
- `pkg/config/compiler_policy_log_inert_deny_4373_test.go` — policy tests; deny/reject logging honesty; warning-only observability behavior pinned.
- `pkg/config/compiler_policy_match.go` — AST policy gate; supported/unsupported/collapsed leaves; strict sound, lenient loses quarantine marker (F1).
- `pkg/config/compiler_policy_match_3113_test.go` — policy tests; strict unsupported-leaf reject but lenient warning-and-compile; supports F1 trace.
- `pkg/config/compiler_policy_match_3142_test.go` — policy tests; swallowed unsupported multi-value tails; strict/lenient behavior shares F1 root.
- `pkg/config/compiler_policy_match_3673_test.go` — policy tests; swallowed structural zone tokens; strict rejection and no over-reject cases covered.
- `pkg/config/compiler_policy_match_address_set_3149_test.go` — policy tests; dangling/empty sets and exclusions; non-empty unresolved content fails closed.
- `pkg/config/compiler_policy_match_application_3144_test.go` — policy tests; app/app-set definedness and lenient sentinel path; no additional root.
- `pkg/config/compiler_policy_match_ssot_4121_test.go` — policy tests; Keys-plus-Children SSOT parity; source/destination/application accumulation covered.
- `pkg/config/compiler_policy_missing_match.go` — AST policy gate; required dimensions strict, warning-only lenient with no typed marker (F1).
- `pkg/config/compiler_policy_missing_match_3044_test.go` — policy tests; complete strict matrix and lenient warning; runtime typed trace for F1.
- `pkg/config/compiler_policy_term_multimatch_2642_test.go` — policy tests; hierarchical/flat multi-match accumulation; no dropped dimensions.
- `pkg/config/compiler_policy_then.go` — policy action AST gates; permit/reject/deny modifiers; strict sound, lenient permit-drop is merged into F1.
- `pkg/config/compiler_policy_then_3114_test.go` — policy tests; unsupported permit modifiers strict/lenient; same tolerant quarantine root as F1.
- `pkg/config/compiler_policy_then_3115_test.go` — policy tests; reject modifiers and bare reject; no allow/deny inversion.
- `pkg/config/compiler_policy_then_deny_3141_test.go` — policy tests; collapsed log/count wiring and unknown modifier rejection; deny remains deny.
- `pkg/config/compiler_policy_then_deny_3374_test.go` — policy tests; orphan log suboptions; strict/lenient syntax handling covered.
- `pkg/config/compiler_policy_then_twonode_3377_test.go` — policy tests; duplicate action-node bypass attempts; guards cover all nodes.
- `pkg/config/compiler_prefix_list_bracket_3996_test.go` — routing tests; bracket/repeated prefix retention and display round-trip; no value loss.
- `pkg/config/compiler_prefix_list_hier_leaf_3843_test.go` — routing tests; hierarchical prefix-list references and undefined negatives; covered.
- `pkg/config/compiler_prefix_list_merge_2641_test.go` — routing tests; duplicate blocks merge; no overwrite loss.
- `pkg/config/compiler_prefix_list_ref_2506_test.go` — routing tests; undefined source/destination references reject; defined path clean.
- `pkg/config/compiler_preid_default_policy_log_2509_test.go` — policy tests; pre-ID log is explicitly warned inert; no admission change.
- `pkg/config/compiler_prewalk.go` — compiler orchestration; AST gates ordered after expansion/prune and before typed compile; warnings accumulated.
- `pkg/config/compiler_protocols.go` — routing compiler; protocol/RA/BGP/OSPF/RIP parsing and numeric helpers; no zone-policy action inversion found.
- `pkg/config/compiler_qualified_nexthop_3871_test.go` — routing tests; per-next-hop preference presence; unrelated to admission.
- `pkg/config/compiler_retired_dataplane_knobs_test.go` — compiler tests; retired knobs warned in strict/lenient; no active forwarding effect.
- `pkg/config/compiler_ribgroup_ref_2226_test.go` — routing tests; RIB references/families and lenient warnings; invalid refs surfaced.
- `pkg/config/compiler_rip_multivalue_3904_test.go` — routing tests; flat/hierarchical multi-values; no truncation.
- `pkg/config/compiler_route_filter_range_2525_test.go` — routing tests; prefix-length range validation and boundaries; no overflow issue.
- `pkg/config/compiler_routing.go` — routing compiler; instances, static routes, PBR and policy terms; typed fields consistently populated.
- `pkg/config/compiler_routing_instance_interface_3904_test.go` — routing tests; repeated interface values retained; no first-only loss.
- `pkg/config/compiler_routing_rules_test.go` — PBR tests; source/destination/action parsing; no security-policy bypass in assigned layer.
- `pkg/config/compiler_rpm_http_scheme_2495_test.go` — RPM tests; HTTP scheme strictness; malformed schemes rejected.
- `pkg/config/compiler_rpm_linklocal_zone_2494_test.go` — RPM tests; link-local IPv6 zone handling; scope preserved.
- `pkg/config/compiler_rpm_routing_instance_2496_test.go` — RPM tests; RI references; no silent fallback.
- `pkg/config/compiler_rpm_scoped_hostname_2493_test.go` — RPM tests; scoped IPv6 hostnames; parser parity covered.
- `pkg/config/compiler_rpm_source_2492_test.go` — RPM tests; source address strict/lenient validation; invalid values signaled.
- `pkg/config/compiler_sampling_source_address_test.go` — sampling tests; family/source address parsing; no policy coupling.
- `pkg/config/compiler_schedulers_3849_test.go` — scheduler tests; duplicate windows and merge behavior; policy scheduler refs checked elsewhere.
- `pkg/config/compiler_security.go` — security dispatcher; merges all security roots, initializes pre-ID state and dispatches policy/zones/NAT/screens.
- `pkg/config/compiler_security_addressbook.go` — address-book compiler; global/local books, qualification and resolution; unresolved policy content guarded.
- `pkg/config/compiler_security_alg.go` — ALG compiler; flag capture only; no policy action widening found.
- `pkg/config/compiler_security_bracket_list_3703_test.go` — security tests; multi-value zones/host-inbound/log lists; token retention covered.
- `pkg/config/compiler_security_flow.go` — flow compiler; session, MSS, trace and SYN controls; no policy verdict rewrite.
- `pkg/config/compiler_security_log.go` — logging compiler; stream/file/event fields; no allow/deny behavior.
- `pkg/config/compiler_security_policy.go` — policy compiler; action/match/default/global/zone typed lowering; empty match slices become runtime any (F1).
- `pkg/config/compiler_security_screen.go` — screen compiler; profile families and limits; strict validators cover unsupported/numeric state.
- `pkg/config/compiler_security_zones.go` — zones compiler; duplicate merge, interfaces, host-inbound overrides and local books; no member loss found.
- `pkg/config/compiler_services.go` — services compiler; DHCP/SNMP/RPM/DDNS/service parsing; no security-policy action coupling found.
- `pkg/config/compiler_signed_port_3606_test.go` — compiler tests; signed/overflow ports strict/lenient behavior; bounds covered.
- `pkg/config/compiler_snmp_trapgroup_2990_test.go` — SNMP tests; malformed/incomplete trap groups and lenient behavior; no firewall effect.
- `pkg/config/compiler_ssh_hardening_4305_test.go` — SSH tests; root-login hardening parse; unrelated to transit policy.
- `pkg/config/compiler_static_nexthop_list_3872_test.go` — routing tests; multi-next-hop lists retained; no truncation.
- `pkg/config/compiler_static_reject_5298_test.go` — routing tests; reject route terminal action; route drop remains distinct from policy.
- `pkg/config/compiler_static_route_inline_iface_3881_test.go` — routing tests; inline interface next-hop parsing; no scope loss.
- `pkg/config/compiler_surface_a_ddns_test.go` — DDNS tests; surface-A fields and warnings; no admission coupling.
- `pkg/config/compiler_syslog_hostmods_4303_test.go` — syslog tests; host modifiers retained; no policy action.
- `pkg/config/compiler_system.go` — system compiler; userspace, auth, syslog and management fields; no zone policy mutation found.
- `pkg/config/compiler_tailgates.go` — compiler orchestration; late validations/warnings and normalization; no gate ordering bypass found.
- `pkg/config/compiler_tcp_mss_range_test.go` — flow tests; MSS range/family/lenient matrix; bounds covered.
- `pkg/config/compiler_tcp_session_seqcheck_test.go` — flow test; no-sequence-check capture; explicit field preserved.
- `pkg/config/compiler_test.go` — compiler tests; multiple strict errors accumulated; gate fan-in covered.
- `pkg/config/compiler_three_color_default_4535_test.go` — CoS tests; default color-blind versus explicit aware; capability behavior pinned.
- `pkg/config/compiler_undefined_ref_2217_test.go` — cross-reference tests; policer/RI/app-set strict and lenient paths; undefined refs surfaced.
- `pkg/config/compiler_uniformgates.go` — typed strict gate dispatcher; strict/lenient downgrade matrix audited; F1 arises after warning-only downgrade.
- `pkg/config/compiler_validate_scheduler_no_window_3860_test.go` — scheduler warning test; no policy verdict impact.
- `pkg/config/compiler_validate_strict.go` — common strict validators; dataplane, trailing tokens, aging, DHCP/VRRP; bounds/lifetimes straightforward.
- `pkg/config/compiler_validate_strict_application.go` — application validators; structure/protocol/ports/timeouts and reference subset; sentinel path works for non-empty refs.
- `pkg/config/compiler_validate_strict_chassis.go` — chassis validator; cluster cardinality/IDs; no policy lowering.
- `pkg/config/compiler_validate_strict_chassis_4434_test.go` — chassis tests; RG count/ID boundaries; covered.
- `pkg/config/compiler_validate_strict_cos.go` — CoS validators; scheduler maps, loss priority and queues; no hidden policy action.
- `pkg/config/compiler_validate_strict_filter.go` — filter validators; refs, protocols, ports, address families, actions and conflicts; fail-closed gates present.
- `pkg/config/compiler_validate_strict_ipsec.go` — IPsec validators; proposal/policy/manual-key references; unsupported states rejected.
- `pkg/config/compiler_validate_strict_nat.go` — NAT validators; apps, addresses, protocols, ports, pools, NPTv6/NAT64/static targets; no new bypass.
- `pkg/config/compiler_validate_strict_observability.go` — log/feed/sampling validators; malformed references and bounds covered.
- `pkg/config/compiler_validate_strict_policy.go` — policy validators; address/app/zone/duplicate/action/log/name checks; strict sound, downstream sentinels checked.
- `pkg/config/compiler_validate_strict_reth_vrrp.go` — RETH/VRRP validator; derived VRID bounds; no zone identity mutation.
- `pkg/config/compiler_validate_strict_reth_vrrp_4826_test.go` — RETH tests; overflow and feature gates; boundaries covered.
- `pkg/config/compiler_validate_strict_routing.go` — routing validators; export/community/auth/router-ID/RIB/route-filter/name refs; unsafe values rejected.
- `pkg/config/compiler_validate_strict_screen.go` — screen validators; profile refs/numerics/unknown fields; strict closed-world behavior.
- `pkg/config/compiler_validate_strict_vrrp.go` — VRRP validator; group ID range; no policy effect.
- `pkg/config/compiler_validate_strict_vrrp_4573_test.go` — VRRP tests; ID boundaries and malformed priority compatibility; covered.
- `pkg/config/compiler_validate_strict_vrrp_priority.go` — VRRP priority validator; packed values and range; integer bounds explicit.
- `pkg/config/compiler_validate_strict_vrrp_priority_5184_test.go` — VRRP tests; packed/hierarchical priority boundaries; covered.
- `pkg/config/compiler_validate_strict_zones.go` — zone validators; reserved names/count/membership/definedness/host tokens; strict references consistent.
- `pkg/config/compiler_validate_vrf_overlap.go` — VRF advisory; bounded overlap scan and family separation; warning-only by design.
- `pkg/config/compiler_validate_vrf_overlap_2387_test.go` — VRF tests; overlaps, PBR and v4/v6 separation; covered.
- `pkg/config/compiler_validate_warn.go` — advisory aggregator; security/NAT/flow/routing honesty warnings; no mutation of verdicts.
- `pkg/config/compiler_validate_warn_cos.go` — CoS advisories; oversubscription/classifier queues; no policy mutation.
- `pkg/config/compiler_validate_warn_ddns.go` — DDNS advisories; provider/url/allowlist validation; no firewall action.
- `pkg/config/compiler_validate_warn_firewall.go` — filter advisories; inert actions/interface-specific/lo0/no-catch-all; no action rewrite.
- `pkg/config/compiler_validate_warn_host_inbound.go` — host/policy advisories; multicast, managed routing, default/deny log and junos-host gaps explicitly surfaced.
- `pkg/config/compiler_validate_warn_nil_3494_test.go` — warning tests; nil slots do not panic; resource safety covered.
- `pkg/config/compiler_validate_warn_routing.go` — routing advisories; DHCP/interface/tunnel/window/RIB gaps; no silent policy mutation.
- `pkg/config/compiler_validate_wireguard.go` — WireGuard validators; peer keys/endpoints/allowed prefixes; strict/lenient values bounded.
- `pkg/config/compiler_zone_interfaces_bracket_5248_test.go` — zone tests; bracket/hierarchical memberships, per-interface host-inbound and undefined members; strong parity coverage.
- `pkg/config/completion_prefix_test.go` — completion tests; prefix resolution only; no runtime semantics.
- `pkg/config/cos_unknown_codepoint_5194_test.go` — CoS test; unknown code points strict versus lenient; no admission impact.
- `pkg/config/ddns_porthost_4589_test.go` — DDNS test; port-only host warning; no firewall effect.
- `pkg/config/ddns_provider_string_test.go` — DDNS tests; URL credential redaction; no forwarding semantics.
- `pkg/config/deactivate_multi_leaf_3975_test.go` — AST tests; deactivate/activate multi-leaf policy and filter members; no residual active value found.

Cross-owner handoff notes: runtime policy tier/session/flow-cache and host-inbound nft/Rust parity were inspected only as called contracts. The Z1 defect below should be handed to the userspace snapshot owner for a quarantine representation; no separate cross-owner finding is duplicated here.


## A3-b4


- `pkg/config/delete_multi_leaf_member_3846_test.go` — AST edit/delete subsystem; checked exact-member deletion, host-inbound and policy multi-leaves, absent-member errors, and keyed-entry isolation. Negative: no widening or sibling deletion gap found.
- `pkg/config/delete_static_nexthop_3872_test.go` — static routing AST edits; checked first/non-first/qualified/last next-hop deletion and not-found handling. Negative: no route-list corruption or silent success found.
- `pkg/config/deterministic_nat_advisory_4559_test.go` — NAT parity advisories; checked IPv4/IPv6/NAPT64 referenced and unreferenced cases. Negative: inert deterministic NAT is surfaced without changing forwarding.
- `pkg/config/deterministic_nat_flatset_3864_test.go` — deterministic NAT parser/compiler; checked order independence, required leaves, ranges, hierarchical parity, and IPv6. Negative: no partial/defaulted deterministic mapping found.
- `pkg/config/dhcp_expired_leases_test.go` — DHCP lease retention schema/compiler; checked dual AST, family independence, zero/bounds/non-integer handling, defaults, and lenient load. Negative: no overflow or cross-family bleed found.
- `pkg/config/dhcp_static_binding_test.go` — DHCP reservations; checked v4/v6 parsing, subnet/family checks, duplicate MAC/address, malformed values, missing address, and lenient behavior. Negative: no invalid binding reaches typed config silently.
- `pkg/config/dpd_typed_value_4878_test.go` — IKE DPD typed leaves; checked flat/hierarchical range and error attribution. Negative: no atoi-zero coercion remains.
- `pkg/config/dual_ast_differential_test.go` — parser differential harness; checked hierarchical/flat equivalence breadth and normalization. Negative: no batch-specific untested divergence identified beyond the finding below.
- `pkg/config/dup_host_local_address.go` — host-local zone ambiguity gate; checked IPv4/IPv6/VRRP identity, interface/unit overrides, lifelines, sorted ownership, strict reject and lenient warning. Negative: known lenient ambiguity is explicitly surfaced; no new bypass found.
- `pkg/config/dup_host_local_address_3718_test.go` — ambiguity gate tests; checked differing/identical services, v4/v6, VRRP, same-zone, lifeline, strict and lenient. Negative: coverage matches the implementation contract.
- `pkg/config/dup_named_blocks.go` — duplicate hierarchical named-block validator; checked interface/group/screen identities, nil nodes, deterministic traversal, and strict/lenient handling. Negative: no duplicate-block overwrite bypass found.
- `pkg/config/dup_named_blocks_5180_test.go` — duplicate-block tests; checked hierarchical rejects, flat merge, family duplication, tolerant warning, and clean singleton. Negative: no missing named scope found.
- `pkg/config/dynamic_address_feed_dup_name_4913_test.go` — dynamic feed identity; checked duplicate name rejection. Negative: no map overwrite ambiguity found.
- `pkg/config/dynamic_address_interval_4879_test.go` — feed interval typed validation; checked flat/hierarchical invalid values, diagnostics, and valid compile. Negative: no zero/default coercion found.
- `pkg/config/event_options_4423_test.go` — event-options edits/merge; checked wrapped not-found errors and duplicate policy merge. Negative: no silent delete or policy overwrite found.
- `pkg/config/event_options_match.go` — event attribute parser/validator; checked regex compilation, event scoping, known-field closed world, malformed input, and strict/lenient split. Negative: runtime/validator grammar is aligned for recognized expressions.
- `pkg/config/event_options_match_test.go` — attribute-match tests; checked valid/invalid regex, malformed lines, unknown fields, event-name scope, direct validators, and lenient warning. Negative: no dropped constraint on strict commit found.
- `pkg/config/event_options_within.go` — temporal event gate; checked numeric bounds, duration overflow, trigger grammar, on/until conflict, missing thresholds, duplicate AST shapes, and lenient fail-closed defense. Negative: no unconditional-fire coercion remains.
- `pkg/config/event_options_within_3751_test.go` — temporal gate tests; checked valid, malformed, contradictory, and lenient cases. Negative: test matrix exercises dangerous zero-value paths.
- `pkg/config/fable167_advisory_test.go` — vSRX parity advisories; checked junos-host source rejection, flow knobs, sync-ICMP, ALG, unknown policy child, and tolerant load. Negative: unsupported behavior is not silently represented as enforced.
- `pkg/config/fbf_fixture_test.go` — filter-based forwarding fixture; checked two-upstream compilation. Negative: no fixture-level route/filter order defect found.
- `pkg/config/filter_match_resolve.go` — firewall symbolic resolution; checked ICMP family/type bounds, numeric canonicalization, named and ranged ports, unknown preservation, and FBF range parity. Negative: unresolved constraints remain fail-closed and strict-rejected.
- `pkg/config/filter_protocol_rust_mirror_3393_test.go` — Go/Rust protocol parity; checked mirror extraction and numeric token handling. Negative: named protocol sets do not drift.
- `pkg/config/firewall_address_except_matchany_4338_test.go` — address except semantics; checked v4/v6 source/destination match-any plus except and specific-positive rejection. Negative: no over-reject of universe-minus-set shape.
- `pkg/config/firewall_address_except_mutex_3359_test.go` — address/prefix-list cross-field validation; checked source/destination and family variants. Negative: conflicting positive/except forms fail strict commit.
- `pkg/config/firewall_address_literal_3433_test.go` — address literal validation; checked malformed, wrong-family, and valid literals. Negative: no malformed address silently broadens a filter.
- `pkg/config/firewall_crossfield_3723_test.go` — filter protocol/port/TCP/ICMP constraints; checked impossible combinations, ICMP code dependency, valid combinations, lenient warnings, and shared application SSOT. Negative: strict path rejects unrepresentable predicates.
- `pkg/config/firewall_dscp_drift_3309_test.go` — DSCP SSOT drift test; checked resolver/table parity. Negative: no code-point table mismatch found.
- `pkg/config/firewall_dscp_range_3309_test.go` — DSCP/traffic-class validation; checked names, numeric bounds, rewrite values, IPv6, and valid cases. Negative: no nft/userspace value widening found.
- `pkg/config/firewall_filter_expand.go` — retired-eBPF expansion arithmetic; checked saturating multiplication, minimum factors, prefix-list accounting, clamp, allocation bound, and live-userspace non-use. Negative: no integer wrap or live hot-path cost found.
- `pkg/config/firewall_filter_expand_overflow_5456_test.go` — expansion overflow tests; checked >uint32, cap boundary, warning-not-reject, normal values, and large valid config. Negative: clamp/diagnostic invariant is covered.
- `pkg/config/firewall_filter_regressions_4422_test.go` — filter grammar regressions; checked bare port, TCP state contradiction, and source port on ICMP. Negative: impossible terms reject.
- `pkg/config/firewall_from_unenforced_3307_test.go` — unsupported `from` leaves; checked inet/inet6 rejection and enforced allowlist. Negative: no silently ignored matcher found.
- `pkg/config/firewall_multivalue_2545_test.go` — multi-value filter parsing; checked hierarchical, repeated flat, and bracket lists. Negative: no first-value-only collapse found.
- `pkg/config/firewall_port_except_2622_test.go` — port-except parsing; checked hierarchical/flat/bracket/inet6 preservation. Negative: no missing negation token found.
- `pkg/config/firewall_port_except_mutex_3297_test.go` — port positive/except exclusion; checked source/destination/family and one-sided valid forms. Negative: no match-all except widening found.
- `pkg/config/firewall_ri_conflict_3308_test.go` — FBF terminal action conflicts; checked discard/reject/accept and inet6. Negative: routing-instance cannot coexist with contradictory terminal actions.
- `pkg/config/firewall_ri_output_direction_3432_test.go` — FBF direction validation; checked output rejection, input acceptance, non-FBF output, inet6, and lenient warning. Negative: strict path prevents unsupported egress PBR.
- `pkg/config/firewall_symbolic_match_3205_test.go` — ICMP/named-port resolution tests; checked family names, unknown/out-of-range, except, hyphenated aliases, ranges, and numeric preservation. Negative: resolver fail-closed contract is covered.
- `pkg/config/firewall_terminal_conflict_4375_test.go` — terminal action uniqueness; checked pairwise conflicts, v6, modifiers, singleton, and idempotent duplicates. Negative: no ambiguous verdict survives strict commit.
- `pkg/config/firewall_terminal_nextterm_5142_test.go` — `next term` terminal conflicts; checked accept/reject/discard, v6, modifier-only and standalone forms. Negative: no terminal-plus-fallthrough ambiguity found.
- `pkg/config/flow_aging_3440_test.go` — session aging validation; checked schema bounds, cross-fields, unknowns, valid cases, lenient warning, and config-only advisories. Negative: no invalid timeout reaches runtime silently.
- `pkg/config/flow_traceoptions_file_3420_test.go` — trace filename security; checked traversal rejection, basename acceptance, and lenient warning. Negative: strict path blocks path escape.
- `pkg/config/flow_traceoptions_filter_3422_test.go` — flow trace filter grammar; checked malformed prefixes, protocol-only/session flag, valid filters, and lenient warning. Negative: no silently dropped narrowing on strict path.
- `pkg/config/flow_traceoptions_size_3424_test.go` — trace rotation bounds; checked invalid/valid size/files and lenient warning. Negative: no unchecked allocation/rotation value found.
- `pkg/config/flowserver_template_ref_test.go` — flow export references; checked v9/IPFIX dangling, defined, absent, and lenient warning. Negative: strict path does not silently omit templates.
- `pkg/config/freetext.go` — config text injection defenses; checked C0/DEL, annotation comment delimiters, recursive paths, strict validation, lenient in-place sanitation, and ownership. Negative: no Format-to-Parse injection found.
- `pkg/config/freetext_test.go` — free-text tests; checked newline/control/comment injection, annotation round-trip, sanitizer chains, lenient sanitation, and helpers. Negative: both strict and compatibility paths are covered.
- `pkg/config/frr_clusterid_origin_4919_test.go` — BGP cluster-id/origin validation; checked schema, diagnostic values, and unit validator. Negative: invalid FRR values do not compile silently.
- `pkg/config/global_policy_zone_scope_3680_test.go` — scoped-global zone semantics; checked wildcard exactness, explicit `any`, and scoped non-over-inclusion. Negative: no global policy over-application found.
- `pkg/config/host_inbound_dup_block_4544_test.go` — duplicate host-inbound merge; checked zone/interface merge, dedup, and singleton identity. Negative: repeated blocks do not overwrite admission sets.
- `pkg/config/host_inbound_effective_3720_test.go` — per-interface host-inbound inheritance; checked physical-to-unit union, inherited-only, and physical exact scope. Negative: display/effective set matches additive semantics.
- `pkg/config/host_inbound_fulladmit_warn_3226_test.go` — broad host admission advisory; checked `all`, specific service, and per-interface scope. Negative: packet-wide admission is operator-visible.
- `pkg/config/host_inbound_managed_routing_mismatch_4455_test.go` — FRR/host-inbound mismatch advisory; checked managed protocol without admission. Negative: control-plane false deny is surfaced.
- `pkg/config/host_inbound_match_3627_test.go` — host-inbound tuple SSOT; checked service/protocol family, port, ICMP, reject, full-admit, and L2 shapes. Negative: Go simulator tuples match intended enforcement table.
- `pkg/config/host_inbound_multicast.go` — multicast host-control catalog; checked family groups, all-expansion, sorting, and advisory-only status. Negative: known packet-wide multicast gap is documented and warned, not misrepresented as enforced.
- `pkg/config/host_inbound_multicast_warn_4455_test.go` — multicast warnings; checked multicast/unicast/none/all/per-interface and catalog shape. Negative: warning coverage matches deferred enforcement boundary.
- `pkg/config/host_inbound_per_iface_3362_test.go` — per-interface host-inbound parser/gate; checked parse, unknown strict reject, and known acceptance. Negative: interface token typos cannot bypass validation.
- `pkg/config/host_inbound_rust_parity_test.go` — Go/Rust host token parity; checked service/protocol/family/L2 token sets by source extraction. Negative: token-domain drift is guarded; tuple-value parity remains separate but inspected via SSOT tests.
- `pkg/config/host_inbound_tokens.go` — host-inbound token/tuple SSOT; checked families, aliases, L2 exclusions, full-admit, reject, ports, ICMP, deterministic all expansion, and runtime normalization contract. Finding `A3-b4-01`.
- `pkg/config/host_inbound_tokens_test.go` — token strict/lenient tests; checked unknown, wrong-case strict rejection, known values, routing/L2/all, and tolerant warning. Finding `A3-b4-01`: no tolerant wrong-case projection test.
- `pkg/config/host_inbound_view.go` — host-inbound diagnostic model; checked additive parent/unit overrides, lifeline visibility, default-deny reasons, sorting, cloning, and nil safety. Negative: show/interface view does not contradict effective admission.
- `pkg/config/host_inbound_view_3654_test.go` — view tests; checked union, reasons, effective sets, zone posture with overrides, and interface render. Negative: no presentation false permit/deny found.
- `pkg/config/host_inbound_view_lifeline_3682_test.go` — lifeline diagnostics; checked default/configured lifelines and interface/zone rendering. Negative: bypass is visible and matcher parity is covered.
- `pkg/config/ike_policy_chain_ref_test.go` — IKE reference chain; checked gateway/policy/proposal dangling cases, direct proposals, orphans, strict load-bearing behavior, and both lenient constructors. Negative: active VPN chains cannot silently disappear.
- `pkg/config/inactive.go` — inactive subtree pruning; checked clone ownership, nils, recursion, group-expansion ordering, metadata preservation, and common-path allocation. Negative: inactive security statements are excluded without mutating source AST.
- `pkg/config/inactive_test.go` — inactive behavior tests; checked parser/format/XML/JSON/set/HA/groups/schema/compare and mutation isolation. Negative: no reactivation or HA divergence found.
- `pkg/config/inline_inactive_4335_test.go` — inline inactive modifiers; checked DNAT pool port removal, absence equivalence, active and leading markers, and generic parse. Negative: deactivated modifier does not leak into NAT.
- `pkg/config/interface_parity_4308_test.go` — interface vSRX knobs; checked compile, advisories, and unset behavior. Negative: unsupported knobs are visible rather than silently claimed.
- `pkg/config/ipip_tunnel_dead_warn_4788_test.go` — IPIP dead configuration warning; checked inert tunnel detection. Negative: no silent nonfunctional tunnel claim.
- `pkg/config/ipsec_dhgroup_test.go` — IKE/IPsec DH parsing; checked prefixed and numeric variants, phase-1 regression, and helper. Negative: no group zero/default downgrade found.
- `pkg/config/ipsec_proposal_ref_test.go` — IPsec proposal references; checked dangling/missing/resolved/name-equal/no-policy and lenient warning. Negative: strict path prevents silent VPN omission.
- `pkg/config/json_repeated_leaf_5194_test.go` — JSON formatter; checked repeated leaf array preservation. Negative: no last-value loss found.
- `pkg/config/junos_host_deny.go` — direct-host Junos policy projection; traced exact/from-any/global ordering, source/application resolution, permits, family/fragment exemptions, netdev VLAN/RETH identity, warning suppression, and nft compatibility. Finding `A3-b4-01`.
- `pkg/config/junos_host_deny_test.go` — projection tests; checked tier composition, whole-program gate, lowercase IKE/ident flags, ambiguous trunks, and cross-dimension permits. Finding `A3-b4-01`: tolerant wrong-case coarse tokens are absent.
- `pkg/config/lenient_fw_cos_4953_test.go` — tolerant firewall/CoS gates; checked TCP flags and numeric code points strict-vs-lenient. Negative: warnings preserve legacy load without hidden widening in these fields.
- `pkg/config/lexer.go` — lexer; checked comment/string errors, bracket-list iteration, IPv6 endpoint recognition, positions, escapes, EOF, and recursion/memory behavior. Negative: no stack recursion or truncation acceptance found.
- `pkg/config/lifeline.go` — host-inbound lifeline matching; checked base/unit stripping, configured cluster names, defaults, nil maps, and documented broad `fab*` exception. Negative: no new HA lockout path found; broad exemption is known/design-tracked.
- `pkg/config/log_profile_schema_test.go` — log profile schema; checked flat/hierarchical accepted shapes. Negative: no schema false reject found.
- `pkg/config/log_profile_test.go` — log profile compile/references; checked dual AST, dangling/valid/absent stream, lenient warning, and inactive profile. Negative: strict path prevents silent stream loss.
- `pkg/config/log_stream_config_3349_test.go` — security log stream validation; checked typo fields, ports including nested host, event mode/format, valid values, and lenient warning. Negative: no malformed destination silently defaults.
- `pkg/config/log_stream_tls_profile_3350_test.go` — TLS profile support gate; checked strict nested rejects, plain TLS, and lenient warning. Negative: unsupported certificate profile is not claimed as enforced.
- `pkg/config/login_custom_class_4304_test.go` — login authorization parity; checked custom class advisory/mapping, undefined class, privilege escalation, and deny-command warning. Negative: no custom-class privilege broadening found.
- `pkg/config/login_password_test.go` — password hash/auth parsing; checked hash formats, dual AST, schema, and unauthenticated-user warning. Negative: malformed hashes reject and secrets remain typed.
- `pkg/config/login_username_4895_test.go` — username injection validation; checked newline/metacharacters/uppercase across dual AST and valid names. Negative: no account/file injection path found.
- `pkg/config/named_port_caseinsensitive_3372_test.go` — application port canonicalization; checked mixed-case numeric lowering equivalence and alias-table drift. Negative: raw mixed-case alias does not reach case-sensitive runtime.
- `pkg/config/nat_range_wrap_5194_test.go` — NAT full-domain expansion; checked terminal-address increment wrap. Negative: no infinite loop at max address.
- `pkg/config/natpool.go` — operational source-NAT pool resolution; checked unknown-vs-empty distinction, CIDR/bare v4/v6, malformed skip, nils, and session-clear filter semantics. Negative: unknown pool cannot degrade to clear-all.
- `pkg/config/natpool_test.go` — NAT pool resolver test; checked address and address-list networks plus unknown handling. Negative: filter identity behavior is covered.
- `pkg/config/parser.go` — recursive-descent and flat-command parser; checked depth cap/drain, stray braces, token errors, semicolon remainder rejection, inactive markers, recovery progress, ownership, and bounds. Negative: no silent truncation or unbounded recursion found.
- `pkg/config/parser_ast_test.go` — broad parser/compiler suite; checked lexer, AST edits, groups, formatting, schema, dataplane type, policies, host-inbound, NAT, RPM, CoS/policers, JSON/XML, and references. Negative: broad positive/negative coverage passes; no candidate survived targeted review.
- `pkg/config/parser_bracket_list_2419_test.go` — bracket-list parsing; checked hierarchical parity, edge cases, and compile. Negative: no list member collapse found.
- `pkg/config/parser_class_of_service_test.go` — CoS parser/compiler; checked dual AST, bounds, aggregate percentages, equal-flow requirements, queue/FC uniqueness, bindings, inheritance, warnings, and oversubscription. Negative: no integer/ownership/hot-path configuration defect found.
- `pkg/config/parser_cluster_test.go` — chassis cluster parser/compiler; checked sync/HA options, RETH, IP monitoring, VIP ownership, fabric membership, node/slot mapping, and per-unit tunnels. Negative: no cross-node ownership or invalid fabric acceptance found.
- `pkg/config/parser_fbf_test.go` — FBF composition; checked flat/hierarchical policy/filter assembly. Negative: no AST-shape routing divergence found.
- `pkg/config/parser_ipmonitoring_test.go` — IP monitoring; checked dual AST, interface next-hop validation/lease keys/idempotence, and DHCP interface identity. Negative: no invalid failover route accepted.
- `pkg/config/parser_recursion_dos_hb164_test.go` — parser DoS tests; checked bracket flood, depth error, deep non-crash, and normal config. Negative: stack bounds are exercised.
- `pkg/config/parser_routing_test.go` — routing parser/compiler; checked static/ECMP/next-table, policies, BGP/OSPF/ISIS, auth/BFD, tunnels, bridge/IRB, RIB groups, LLDP, mirroring, VLAN/interface identity, and family gates. Negative: no route/PBR ordering or family widening candidate found.
- `pkg/config/parser_rpm_pin_test.go` — RPM pinning; checked dual AST, validation, band cap, and table collision. Negative: no invalid pin state accepted.
- `pkg/config/parser_security_test.go` — security parser/compiler; checked NAT/NAT64/NPTv6, filters, screens, policies/global policies, applications/sets, host-inbound IPsec, reject/deny, flow logging, IPsec/IKE, fragments/flexible match, and family variants. Negative: broad zone-policy paths pass; missing tolerant wrong-case projection is recorded in `A3-b4-01`.
- `pkg/config/parser_semicolon_5194_test.go` — flat command terminator; checked tokens after semicolon. Negative: trailing destructive statement cannot be silently discarded.
- `pkg/config/parser_services_test.go` — services/interface parser; checked RPM, feeds, VLAN/filter assignment, LAG/LACP, flexible VLAN, proxy ARP, flow flags, and warnings. Negative: no interface identity or service parser candidate found.
- `pkg/config/parser_stray_brace_4862_test.go` — unmatched-brace handling; checked leading/trailing/middle braces, trailing config retention, deep valid nesting, and position. Negative: parser no longer accepts truncated security tail.
- `pkg/config/parser_system_test.go` — system parser/compiler; checked syslog, DHCP, auth/API, SNMPv3, NTP/DNS, archival, dataplane selection, groups, and SSH KEX. Negative: no secret, bounds, or retired-backend acceptance candidate found.
- `pkg/config/policer_rate_validate_5299_test.go` — policer rate parsing; checked valid units, bare burst, invalid values, tolerant warning, and overflow-to-zero helper. Negative: strict commit blocks overflow/default coercion.
- `pkg/config/policy_community_ref_test.go` — routing policy community references; checked from/delete dangling and valid, set/add literals, multi-delete, and lenient warning. Negative: no silent missing dependency on strict path.
- `pkg/config/policy_from_multileaf_2689_test.go` — routing policy multi-leaves; checked community/prefix-list/as-path across bracket, hierarchical, and sibling forms. Negative: no first-member collapse found.
- `pkg/config/policy_log_action_3060_test.go` — security policy logging grammar; checked zone/global bare log reject, valid session-init, and lenient warning. Negative: no ambiguous log action survives strict commit.
- `pkg/config/policy_match_excluded_test.go` — policy address exclusion; checked excluded flags, defaults, any-family normalization, schema typos, valid forms, and lenient warning. Negative: no except match-all widening on strict path.
- `pkg/config/policy_rematch_advisory_test.go` — policy rematch mode; checked bare/extensive/absent advisories. Negative: unsupported expensive semantics are visible.
- `pkg/config/policy_reserved_chain_name_5442_test.go` — generated chain namespace; checked reserved suffix reject, normal name, and lenient warning. Negative: no generated-chain collision on strict path.
- `pkg/config/policy_reserved_redist_name_5116_test.go` — redistribution namespace; checked reserved suffix reject, normal name, and lenient warning. Negative: no generated policy collision on strict path.
- `pkg/config/policy_terminal_action_3043_test.go` — policy terminal verdict; checked missing/conflicting actions, zone/global diagnostics, exact action, and lenient default-deny. Negative: compatibility path fails closed.
- `pkg/config/policy_zone_matrix_4422_test.go` — zone-pair action matrix; checked independent permit/deny/reject compilation. Negative: no action bleed between zone pairs.
- `pkg/config/policy_zone_ref_test.go` — policy zone references; checked undefined, defined, wildcard, Junos-host, special tokens, enforcement, and lenient warning. Negative: strict path rejects dangling zones and wildcard behavior is pinned.
- `pkg/config/predefined.go` — predefined applications/sets and expansion; checked protocols/ports/ICMP, user precedence, nil slots, nesting/depth/cycles, unknown members, and address-set expansion. Negative: no nil panic or empty-set fail-open found.
- `pkg/config/predefined_app_sets_4102_test.go` — predefined app-set tests; checked resolve, policy commit, user shadowing, and unknown rejection. Negative: standard vSRX bundles expand non-empty.
- `pkg/config/predefined_icmp_3020_test.go` — predefined ping apps; checked v4/v6 echo-request type constraints. Negative: ping does not widen to all ICMP.
- `pkg/config/predefined_nil_appset_5179_test.go` — nil app-set compatibility; checked no panic. Negative: corrupt tolerant map slot fails deterministically.
- `pkg/config/protocols_multileaf_2587_test.go` — routing policy/protocol multi-leaves; checked OSPF/OSPFv3/BGP group/neighbor/ISIS/community across dual AST. Negative: no repeated import/export/community member loss found.


## A3-b5


### Strict/lenient policy matrix

| Dimension | Strict commit / commit-check | Lenient load / HA sync | Runtime consequence checked |
|---|---|---|---|
| Typed leaves and key slots | `SchemaValidateWithDefinitions` rejects malformed values, missing values, excess scalar tails, closed-world unknowns, redaction placeholders, and invalid keys before compile. | Configstore downgrades the same schema failure to a warning and compiles the sanitized/expanded tree. | Render/snapshot belts must skip, quarantine, or match-none malformed state; F001 and F002 show two strict acceptance gaps before this split. |
| Zones and interfaces | Reserved names, undefined interfaces/zones, duplicate membership, stable-ID collisions, host-inbound tokens, and screen references reject. | Warnings preserve boot; collision/undefined objects are quarantined or omitted. | Logical VLAN/RETH identity and per-interface host-inbound union were traced through typed fields; previously reported exact-unit and tagged-RETH defects are dedup handoffs. |
| Global/scoped-global/Junos-host/default | Zone sets compile as plural `FromZones`/`ToZones`; mixed `junos-host` scope and undefined zones reject; default policy initializes to deny. | Invalid scopes warn and unindex; singular compatibility fields narrow rather than widen. | Exact/wildcard/global/host/default ordering remains fail-closed. Same-version old-helper multi-zone narrowing is already owned by codex-review-179. |
| Applications and app sets | Structure, protocols, ports, ICMP type/code, unknown terms, references, collisions and generated names reject. | Invalid applications retain sentinels and resolve to unsupported/match-none. | Policy/NAT consumers do not turn malformed app constraints into any; no allocation or lock enters the packet path from this batch. |
| Screens and filters | Unknown screen leaves, non-positive thresholds, bad references, firewall protocols/ports/tcp-flags and action bounds reject. | Screen defects warn and become disabled/match-none; filter belts refuse unrepresentable terms. | Screen inventory parity was checked; alarm-without-drop omission is a prior duplicate. F003 is syntax acceptance without match widening. |
| NAT/PBR/routing order | NAT addresses/ports/actions and routing references/table IDs are checked before publication. | Bad NAT criteria use unusable/match-none markers; colliding VRFs are quarantined; malformed route-filter prefixes are skipped. | No denied packet was found forwarding in these files. F002 makes a valid policy route-filter match nothing, a false-deny. |
| Publication, HA, helpers, counters/API | Stable IDs and compatibility singular/plural fields are deterministic; show helpers sort and nil-check. | Tolerant paths preserve boot while runtime belts suppress unsafe rows. | No snapshot mutation, packet buffer ownership, per-packet lock, or unbounded hot-path allocation exists in the assigned production files. |

### Typed-to-compiled field ledger

| Authored surface | Typed field(s) | Compiler/runtime consumer | Result |
|---|---|---|---|
| Security zones/interfaces/host inbound | `ZoneConfig.Interfaces`, `HostInboundTraffic`, `InterfaceHostInbound`, `ScreenProfile` | zone compiler, host-local gate, userspace screen snapshot, zone show APIs | Additive per-interface semantics and strict token/reference checks hold; invalid state narrows admission. |
| Zone/global policies/default | `ZonePairPolicies`, `Policy.Match.FromZones/ToZones`, `Policy.Action`, `SecurityConfig.DefaultPolicy` | policy snapshot and Rust five-tier evaluation, simulator/show compatibility fields | Default is deny; scoped sets remain plural through current helpers; old singular narrowing is duplicate-owned. |
| Applications/app sets | `Application.Terms`, protocol/port/ICMP invalid-token sentinels, `ApplicationSet` members | strict application gates, policy and NAT expansion, Rust application catalog | Malformed or unresolved constraints become unsupported/match-none, not any. |
| Screens | `ScreenProfile` booleans, thresholds, `BadNumeric`, `UnknownLeaves`, `AlarmWithoutDrop` | strict screen gates, userspace snapshot, REST/gRPC/CLI inventory | Enforcement values are bounded; prior inventory omission is a handoff duplicate. |
| Firewall filters | typed protocol/ports/ICMP/tcp-flags/flex-match fields in `FirewallFilterTerm` | filter snapshot and Rust matcher | Numeric/protocol bounds hold; F003 accepts malformed parentheses but preserves the parsed bit constraint. |
| Source/destination/static NAT | `NATMatch` plural axes and invalid sentinels, `NATThen`, pool raw/bounds fields | source/DNAT/static snapshot builders and Rust first-match tables | Invalid configured constraints fail closed. Open-world source-NAT unknown actions compile as no-action rows and are skipped, a documented non-widening debt. |
| Routing/route filters | `PolicyTerm.RouteFilters`, `RouteFilter.Prefix/MatchType`, stable routing table IDs | FRR prefix-list/route-map renderer and VRF programming | F002 accepts a match keyword in the prefix slot; render belt skips it and forces NOMATCH. |
| IKE/IPsec DH groups | `IKEProposal.DHGroup`, `IPsecProposal.DHGroup` | swanctl proposal construction via `formatDHGroup` | F001: positive-only schema validation exceeds the renderer's supported group map. |
| Interfaces/RETH/tunnels/VRRP | interface units/VLAN IDs, redundant-parent maps, `TunnelConfig`, stable tunnel IDs, `VRRPGroup` | interface snapshots, show APIs, tunnel builder, VRRP managers | Deep copies and stable-ID collision belts hold; known runtime RETH/VRRP issues are owned elsewhere. |
| System/logging/SNMP/sampling | typed syslog, login, time-zone, SNMP client, sampling and RPM fields | host renderers, show-log allowlist, SNMP request authorization, exporters/probes | Injection and numeric bounds hold. Equal-prefix SNMP tie and URL path redaction are prior duplicates. |

### Per-path ledger

- `pkg/config/quoted_inactive_4348_test.go` — config serialization/secrets; redaction, round-trip escaping, inactive markers, immutable values; secret marshaling and quoted inactive handling are stable; URL path redaction root is duplicate-owned by codex-review-179.
- `pkg/config/quotekey_roundtrip_3854_test.go` — config serialization/secrets; redaction, round-trip escaping, inactive markers, immutable values; secret marshaling and quoted inactive handling are stable; URL path redaction root is duplicate-owned by codex-review-179.
- `pkg/config/reserved_zone_name_3055_test.go` — security zones/policy scope; reserved identities, scoped-global sets, junos-host/default behavior, strict/lenient quarantine; zone references and wildcard sets are fail-closed; old-helper multi-zone narrowing and host-override roots are duplicate-owned.
- `pkg/config/reth_show.go` — RETH interface display/identity; VLAN/unit resolution, local-member selection, nil safety, API/CLI parity; display helpers are bounded and deterministic; tagged-RETH runtime identity defect is duplicate-owned outside this batch.
- `pkg/config/ribgroup_leak_warn_3876_test.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/router_id_2980_test.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/routing_adjacency_4285_test.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/routing_export_ref_test.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/routinginstanceid.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/routinginstanceid_test.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/rpm_probe_dup_block_4820_test.go` — services/sampling/RPM schema; numeric bounds, duplicate block merge, conflict handling, strict/lenient warnings; negative rates/conflicts reject and duplicate blocks merge without unbounded runtime work.
- `pkg/config/sampling_input_rate_5244_test.go` — services/sampling/RPM schema; numeric bounds, duplicate block merge, conflict handling, strict/lenient warnings; negative rates/conflicts reject and duplicate blocks merge without unbounded runtime work.
- `pkg/config/sampling_instance_conflict_test.go` — services/sampling/RPM schema; numeric bounds, duplicate block merge, conflict handling, strict/lenient warnings; negative rates/conflicts reject and duplicate blocks merge without unbounded runtime work.
- `pkg/config/schema.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_chassis.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_closedworld_ike_proposal_4313_test.go` — IKE/IPsec schema; strict enum/DH bounds, proposal typing, lenient-load compatibility, vSRX rendering parity; closed-world and valid-value coverage is sound; F001 lacks groups 17/18 and unsupported-group rejection coverage.
- `pkg/config/schema_closedworld_ipsec_4313_test.go` — IKE/IPsec schema; strict enum/DH bounds, proposal typing, lenient-load compatibility, vSRX rendering parity; closed-world and valid-value coverage is sound; F001 lacks groups 17/18 and unsupported-group rejection coverage.
- `pkg/config/schema_closedworld_ipsec_proposal_4313_test.go` — IKE/IPsec schema; strict enum/DH bounds, proposal typing, lenient-load compatibility, vSRX rendering parity; closed-world and valid-value coverage is sound; F001 lacks groups 17/18 and unsupported-group rejection coverage.
- `pkg/config/schema_closedworld_nat64_4313_test.go` — security NAT schema/tests; scope, address/port bounds, action closed-world policy, strict/lenient match-none belts; DNAT/static-NAT bounds and targets are gated; source-NAT open-world action debt is explicitly documented and runtime skips no-action rules.
- `pkg/config/schema_closedworld_nat_then_4313_test.go` — security NAT schema/tests; scope, address/port bounds, action closed-world policy, strict/lenient match-none belts; DNAT/static-NAT bounds and targets are gated; source-NAT open-world action debt is explicitly documented and runtime skips no-action rules.
- `pkg/config/schema_closedworld_natv6v4_4313_test.go` — security NAT schema/tests; scope, address/port bounds, action closed-world policy, strict/lenient match-none belts; DNAT/static-NAT bounds and targets are gated; source-NAT open-world action debt is explicitly documented and runtime skips no-action rules.
- `pkg/config/schema_complete.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_cos.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_cos_buffer_temporal_4228_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_cos_hb166_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_cos_ieee8021_rewrite_4228_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_desc_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_global_zone_list_4415_test.go` — security zones/policy scope; reserved identities, scoped-global sets, junos-host/default behavior, strict/lenient quarantine; zone references and wildcard sets are fail-closed; old-helper multi-zone narrowing and host-override roots are duplicate-owned.
- `pkg/config/schema_ike_enum_3896_test.go` — IKE/IPsec schema; strict enum/DH bounds, proposal typing, lenient-load compatibility, vSRX rendering parity; closed-world and valid-value coverage is sound; F001 lacks groups 17/18 and unsupported-group rejection coverage.
- `pkg/config/schema_interfaces.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_lldp_ttl_4596_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_master_password_prf_4578_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_policy_then_3377_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_policy_then_int_4688_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_route_preference_3771_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_route_qnh_preference_3827_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_routing.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/schema_scheduler_name_3117_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_schedulers.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_security.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_system.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_2008_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_2497_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_2524_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_3895_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_4119_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_chassis_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_cos_rate_percent_4228_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_ddns_hostname_2779_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_ddns_source_address_2780_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_firewall_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_flow_numwidth_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_interfaces_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_route_2448_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_route_filter_test.go` — routing route-filter tests; CIDR/match-type bounds, flat/hierarchical parity, strict/lenient rendering; positive and malformed-CIDR cases pass, but no swapped-slot case covers A3-b5-F002.
- `pkg/config/schema_validate_routing_4285_test.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/schema_validate_system_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validate_trailing_token_3332_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validators.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validators_cos.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validators_ddns.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validators_devicemap.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validators_ipsec.go` — IKE/IPsec schema; strict enum/DH bounds, proposal typing, lenient-load compatibility, vSRX rendering parity; A3-b5-F001: positive-only DH validation admits groups the renderer cannot encode.
- `pkg/config/schema_validators_logging.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validators_network.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validators_routing.go` — routing schema validators; slot typing, CIDR/next-hop parsing, strict/lenient and FRR belts; A3-b5-F002: the shared route-filter validator cannot distinguish prefix from match-type slots.
- `pkg/config/schema_validators_scheduler.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_validators_system.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_walk.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/schema_walk_internal_test.go` — typed schema/walker; flat/hierarchical AST parity, scalar/multi arity, closed-world inheritance, strict/lenient dispatch; bounded commit-time walks and typed bounds are sound; no new root beyond F001/F002.
- `pkg/config/scoped_global_zoneset_4626_test.go` — security zones/policy scope; reserved identities, scoped-global sets, junos-host/default behavior, strict/lenient quarantine; zone references and wildcard sets are fail-closed; old-helper multi-zone narrowing and host-override roots are duplicate-owned.
- `pkg/config/screen_alarm_without_drop_test.go` — security screens; strict numeric/unknown-leaf gates, alarm/drop semantics, inventory/API parity, bounded show work; dataplane-facing flags and thresholds fail closed; prior alarm-without-drop inventory omission is duplicate-owned by codex-review-179.
- `pkg/config/screen_inventory.go` — security screens; strict numeric/unknown-leaf gates, alarm/drop semantics, inventory/API parity, bounded show work; dataplane-facing flags and thresholds fail closed; prior alarm-without-drop inventory omission is duplicate-owned by codex-review-179.
- `pkg/config/screen_numeric_strict_3317_test.go` — security screens; strict numeric/unknown-leaf gates, alarm/drop semantics, inventory/API parity, bounded show work; dataplane-facing flags and thresholds fail closed; prior alarm-without-drop inventory omission is duplicate-owned by codex-review-179.
- `pkg/config/screen_profile_ref_test.go` — security screens; strict numeric/unknown-leaf gates, alarm/drop semantics, inventory/API parity, bounded show work; dataplane-facing flags and thresholds fail closed; prior alarm-without-drop inventory omission is duplicate-owned by codex-review-179.
- `pkg/config/screen_synflood_subthreshold_3315_test.go` — security screens; strict numeric/unknown-leaf gates, alarm/drop semantics, inventory/API parity, bounded show work; dataplane-facing flags and thresholds fail closed; prior alarm-without-drop inventory omission is duplicate-owned by codex-review-179.
- `pkg/config/screen_trailing_token_3332_test.go` — security screens; strict numeric/unknown-leaf gates, alarm/drop semantics, inventory/API parity, bounded show work; dataplane-facing flags and thresholds fail closed; prior alarm-without-drop inventory omission is duplicate-owned by codex-review-179.
- `pkg/config/screen_unknown_strict_3318_test.go` — security screens; strict numeric/unknown-leaf gates, alarm/drop semantics, inventory/API parity, bounded show work; dataplane-facing flags and thresholds fail closed; prior alarm-without-drop inventory omission is duplicate-owned by codex-review-179.
- `pkg/config/secret.go` — config serialization/secrets; redaction, round-trip escaping, inactive markers, immutable values; secret marshaling and quoted inactive handling are stable; URL path redaction root is duplicate-owned by codex-review-179.
- `pkg/config/secret_test.go` — config serialization/secrets; redaction, round-trip escaping, inactive markers, immutable values; secret marshaling and quoted inactive handling are stable; URL path redaction root is duplicate-owned by codex-review-179.
- `pkg/config/set_repeated_leaf_3984_test.go` — configuration display/edit; duplicate contexts, repeated leaves, round-trip preservation, bounded traversal; scoped display and repeated-keyword paths preserve all authored statements.
- `pkg/config/shared_umem_audit_test.go` — userspace config audit; artifact I/O bounds, FIFO/nonregular handling, timeout/resource safety; audit reads are non-gating and bounded; no dataplane hot-path operation occurs here.
- `pkg/config/show_config_dup_context_4562_test.go` — configuration display/edit; duplicate contexts, repeated leaves, round-trip preservation, bounded traversal; scoped display and repeated-keyword paths preserve all authored statements.
- `pkg/config/show_config_repeated_keyword_3980_test.go` — configuration display/edit; duplicate contexts, repeated leaves, round-trip preservation, bounded traversal; scoped display and repeated-keyword paths preserve all authored statements.
- `pkg/config/snmp_clients.go` — SNMP authorization/config; client prefix parsing, longest-prefix/restrict semantics, immutable cache, request-path allocation; malformed entries fail closed and compiled lookups are allocation-free; equal-prefix tie and duplicate-block roots are duplicate-owned.
- `pkg/config/snmp_clients_4289_test.go` — SNMP authorization/config; client prefix parsing, longest-prefix/restrict semantics, immutable cache, request-path allocation; malformed entries fail closed and compiled lookups are allocation-free; equal-prefix tie and duplicate-block roots are duplicate-owned.
- `pkg/config/snmp_clients_4711_test.go` — SNMP authorization/config; client prefix parsing, longest-prefix/restrict semantics, immutable cache, request-path allocation; malformed entries fail closed and compiled lookups are allocation-free; equal-prefix tie and duplicate-block roots are duplicate-owned.
- `pkg/config/snmp_clients_4834_test.go` — SNMP authorization/config; client prefix parsing, longest-prefix/restrict semantics, immutable cache, request-path allocation; malformed entries fail closed and compiled lookups are allocation-free; equal-prefix tie and duplicate-block roots are duplicate-owned.
- `pkg/config/snmp_dup_community_5472_test.go` — SNMP authorization/config; client prefix parsing, longest-prefix/restrict semantics, immutable cache, request-path allocation; malformed entries fail closed and compiled lookups are allocation-free; equal-prefix tie and duplicate-block roots are duplicate-owned.
- `pkg/config/sqm_cookbook_fixture_test.go` — services/sampling/RPM schema; numeric bounds, duplicate block merge, conflict handling, strict/lenient warnings; negative rates/conflicts reject and duplicate blocks merge without unbounded runtime work.
- `pkg/config/ssh_known_hosts_dup_block_4821_test.go` — system/logging schema; injection/path bounds, repeated leaves, strict/lenient render belts, show authorization; typed validators and allowlists reject traversal/control input; no new security-policy admission issue.
- `pkg/config/static_nat_mapped_port_2491_test.go` — security NAT schema/tests; scope, address/port bounds, action closed-world policy, strict/lenient match-none belts; DNAT/static-NAT bounds and targets are gated; source-NAT open-world action debt is explicitly documented and runtime skips no-action rules.
- `pkg/config/static_nat_source_address_3435_test.go` — security NAT schema/tests; scope, address/port bounds, action closed-world policy, strict/lenient match-none belts; DNAT/static-NAT bounds and targets are gated; source-NAT open-world action debt is explicitly documented and runtime skips no-action rules.
- `pkg/config/static_nat_zone_test.go` — security zones/policy scope; reserved identities, scoped-global sets, junos-host/default behavior, strict/lenient quarantine; zone references and wildcard sets are fail-closed; old-helper multi-zone narrowing and host-override roots are duplicate-owned.
- `pkg/config/strict_gate_wiring_canary_test.go` — configuration regression tests; strict/lenient, flat/hierarchical, bounds, negative behavior; assigned regression coverage passes and introduces no production ownership or hot-path risk.
- `pkg/config/syslog_logfile.go` — system/logging schema; injection/path bounds, repeated leaves, strict/lenient render belts, show authorization; typed validators and allowlists reject traversal/control input; no new security-policy admission issue.
- `pkg/config/syslog_logfile_4860_test.go` — system/logging schema; injection/path bounds, repeated leaves, strict/lenient render belts, show authorization; typed validators and allowlists reject traversal/control input; no new security-policy admission issue.
- `pkg/config/system_multileaf_test.go` — system/logging schema; injection/path bounds, repeated leaves, strict/lenient render belts, show authorization; typed validators and allowlists reject traversal/control input; no new security-policy admission issue.
- `pkg/config/system_string_injection_4902_test.go` — system/logging schema; injection/path bounds, repeated leaves, strict/lenient render belts, show authorization; typed validators and allowlists reject traversal/control input; no new security-policy admission issue.
- `pkg/config/tcp_flags.go` — firewall filter grammar; operator parsing, contradiction handling, fail-closed matching, allocation bounds; A3-b5-F003: parentheses are discarded without balance/order validation.
- `pkg/config/tcp_flags_test.go` — firewall filter tests; required/forbidden masks, dangling operators, strict commit integration; broad malformed-operator coverage passes, but unbalanced/reversed-parenthesis cases for A3-b5-F003 are absent.
- `pkg/config/tcp_session_advisory_test.go` — configuration regression tests; strict/lenient, flat/hierarchical, bounds, negative behavior; assigned regression coverage passes and introduces no production ownership or hot-path risk.
- `pkg/config/time_zone_path_validate_5011_test.go` — security zones/policy scope; reserved identities, scoped-global sets, junos-host/default behavior, strict/lenient quarantine; zone references and wildcard sets are fail-closed; old-helper multi-zone narrowing and host-override roots are duplicate-owned.
- `pkg/config/tunnel_perunit_deepcopy_test.go` — tunnel model/identity; stable IDs, group expansion, canonical unit names, deep-copy ownership, helper publication; collision checks and runtime drop belts are deterministic; documented incomplete-tunnel false reject remains pinned, with no new root.
- `pkg/config/tunnelemit.go` — tunnel model/identity; stable IDs, group expansion, canonical unit names, deep-copy ownership, helper publication; collision checks and runtime drop belts are deterministic; documented incomplete-tunnel false reject remains pinned, with no new root.
- `pkg/config/tunnelid.go` — tunnel model/identity; stable IDs, group expansion, canonical unit names, deep-copy ownership, helper publication; collision checks and runtime drop belts are deterministic; documented incomplete-tunnel false reject remains pinned, with no new root.
- `pkg/config/tunnelid_test.go` — tunnel model/identity; stable IDs, group expansion, canonical unit names, deep-copy ownership, helper publication; collision checks and runtime drop belts are deterministic; documented incomplete-tunnel false reject remains pinned, with no new root.
- `pkg/config/types.go` — typed configuration model; field ownership, nil/zero defaults, bounds and compatibility fields; models preserve fail-closed sentinels and immutable publication; no direct packet-path work.
- `pkg/config/types_chassis.go` — typed configuration model; field ownership, nil/zero defaults, bounds and compatibility fields; models preserve fail-closed sentinels and immutable publication; no direct packet-path work.
- `pkg/config/types_cos.go` — typed configuration model; field ownership, nil/zero defaults, bounds and compatibility fields; models preserve fail-closed sentinels and immutable publication; no direct packet-path work.
- `pkg/config/types_interfaces.go` — typed configuration model; field ownership, nil/zero defaults, bounds and compatibility fields; models preserve fail-closed sentinels and immutable publication; no direct packet-path work.
- `pkg/config/types_routing.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/types_security.go` — typed configuration model; field ownership, nil/zero defaults, bounds and compatibility fields; models preserve fail-closed sentinels and immutable publication; no direct packet-path work.
- `pkg/config/types_system.go` — system/logging schema; injection/path bounds, repeated leaves, strict/lenient render belts, show authorization; typed validators and allowlists reject traversal/control input; no new security-policy admission issue.
- `pkg/config/types_test.go` — typed configuration model; field ownership, nil/zero defaults, bounds and compatibility fields; models preserve fail-closed sentinels and immutable publication; no direct packet-path work.
- `pkg/config/value_type.go` — configuration model; typed ownership, nil/zero-value behavior, integer and slice bounds, immutable publication; no independent fail-open, false-deny, lifetime, concurrency, or hot-path defect found.
- `pkg/config/vrf_overlap_budget_5194_test.go` — routing compiler/model; reference validation, table-ID bounds, strict/lenient quarantine, FRR/render parity; references, IDs and collision quarantine are deterministic and fail closed; no new issue beyond A3-b5-F002.
- `pkg/config/vrrp_authentication_4288_test.go` — VRRP schema/model; wire bounds, authentication false-security, preempt timers, strict/lenient behavior; authentication is rejected and timer ranges are bounded; runtime lifecycle findings are owned outside this batch.
- `pkg/config/vrrp_preempt_holdtime_test.go` — VRRP schema/model; wire bounds, authentication false-security, preempt timers, strict/lenient behavior; authentication is rejected and timer ranges are bounded; runtime lifecycle findings are owned outside this batch.

### Cross-owner handoff and dedup notes

- `prior:codex-review-179.md` owns **Equal SNMP client prefixes can bypass restrict by insertion order**; this batch re-traced parsing, immutable cache creation, UDP source extraction and longest-prefix evaluation and did not duplicate it.
- `prior:codex-review-179.md` owns **Screen status inventory omits alarm-without-drop mode**; `ScreenChecks`/`ScreenThresholds` still omit the profile-wide mode, so this remains a handoff rather than a new finding.
- `prior:codex-review-179.md` owns **Same-version old helpers silently narrow multi-zone global denies** and the URL path-redaction root; both were observed while tracing compatibility and secret helpers and suppressed.
- Runtime/dataplane owners should consume F001 at the config-to-swanctl boundary and F002 at the schema-to-FRR boundary. No Rust packet-path ownership change is proposed by this read-only review.


## A3-b6


| Assigned file | Review and substantive negative result |
|---|---|
| `pkg/config/vrrp_track_secret_5195_test.go` | Read both packed-key strict and lenient cases. Diagnostics derive a value-free VRRP group identity and assertions scan every warning; no secret-bearing fallback or missing paired path survived. |
| `pkg/config/vrrp_track_test.go` | Read all nested, legacy sibling, duplicate, malformed-cost, precedence, and round-trip cases. Strict duplicate/range rejection and lenient first-wins neutralization are paired; costs are bounded before runtime use and all test fixtures are finite. No new allow/deny or resource defect found. |
| `pkg/config/vrrp_v6_test.go` | Checked hierarchical/flat IPv6, dual-stack same-VRID separation, and IPv4 regression control. Family identity remains tied to the parent address/VIP and same VRID across families does not overwrite compiled groups. No collision or false denial found. |
| `pkg/config/vrrp_vaddr_subnet_3013_test.go` | Checked out-of-subnet and cross-family rejects against in-subnet, second-subnet, dual-family, owner, and lenient-warning controls. The gate checks every matching-family unit subnet and does not narrow valid secondary-subnet VIPs. |
| `pkg/config/web_management_auth_4047_test.go` | Checked HTTP/HTTPS off-loopback deny cases, user/API-key allow cases, loopback/absent controls, and tolerant warning behavior. Runtime loopback clamping is the lenient fail-closed backstop; no unauthenticated off-loopback admission path was exposed by this slice. |
| `pkg/config/wireguard_allowedips_malformed_5194_test.go` | Checked malformed CIDR strict reject, both tolerant entry points, and valid host-bit canonicalization. Malformed routes are not admitted on commit and tolerant behavior remains visible without widening a peer route. |
| `pkg/config/wireguard_multipeer_test.go` | Read every test: dual AST/list shapes, peer identity, local keys/ports, endpoints/families, AllowedIPs ownership, PSKs, and redaction. Exact cross-peer prefix collisions deny while legitimate LPM overlap and same-peer repeats allow; positive and negative controls are paired and bounded. No new cryptokey-routing admission/denial defect found. |
| `pkg/config/xfrmi.go` | Traced `XFRMIfNameAndID` and bind-interface validation into the AST collision gate and routing reconcile backstop. Index/unit bounds prevent truncation; zero IDs reject; distinct aliases sharing an ID are rejected/quarantined by the established #2933/#5297 root. No novel zone-identity defect found. |
| `pkg/config/xfrmi_test.go` | Checked valid base/unit identity pins and invalid empty/name/index/unit controls. The narrow helper test omits some lexical variants, but those map to the already cataloged bind-interface validation/collision root and do not establish a new bounded finding. |
| `pkg/config/zone_count_cap_test.go` | Checked nil/small/at-cap/over-cap and full compile controls. The count gate is inclusive at 65,533, while the earlier O(n) hash-collision gate remains the effective protection; no off-by-one, sentinel admission, or unbounded packet-path work found. |
| `pkg/config/zone_dup_block_4818_test.go` | Checked two/three duplicate top-level zone blocks, per-interface host-inbound union, address books, scalar behavior, and single-block control. Find-or-create preserves memberships and admission tokens across sibling blocks. The known exact-unit cross-zone override issue is separately deduplicated below. |
| `pkg/config/zone_interface_defined_4515_test.go` | Checked undefined strict denial, tolerant warning, ordinary definitions, implicit `lo0`, and IPsec-created `st` interfaces. Referenceability is intentionally generous only for materialized interfaces; unresolved members remain traffic-inert on tolerant load. No unintended admission found. |
| `pkg/config/zone_interface_membership_test.go` | Checked exact duplicate, bare/unit overlap, same-zone repetition, distinct-unit split, ordinary config, and strict/lenient behavior. Conflict keys mirror configured-unit expansion and preserve valid VLAN unit separation. The tolerant first-writer rule is deterministic; the already tracked exact-unit host-inbound override root was not re-filed. |
| `pkg/config/zone_local_unqualify_3358_test.go` | Checked qualification round-trip, malformed/plain-token rejection, display mapping, nil preservation, and non-mutation. Synthetic names cannot be confused with ordinary address tokens under the slash-free authored-name invariant. |
| `pkg/config/zoneid.go` | Read every function and traced all consumers. FNV identity is frozen and folded to `[1,65533]`; strict collision detection unions pre-expansion and node-expanded views; lenient quarantine deterministically keeps the sorted-first owner and userspace scrubs zones, interfaces, scoped/global policy references before publication. Work is config-time O(z log z), immutable after publication, and not on the packet hot path. No novel collision-based permit/deny defect survived dedup/refutation. |
| `pkg/config/zoneid_test.go` | Checked hash pins, zero/reserved exclusion, pure-function stability, strict/lenient collision paths, HA group symmetry, runtime quarantine, owner lookup, and ordinary controls. Tests pair rejection with non-collision acceptance and pin operator-visible degraded state. No missing assigned invariant found. |

Cross-file negative checks: zone ID `0` remains unknown/unassigned; configured IDs cannot overlap the `65534` junos-host or `65535` global sentinels; quarantined zones are removed before Rust publication; their interfaces become unzoned and their exact/scoped-global policies are removed, producing default denial rather than another zone's admission. Strict membership rejects ambiguous interface ownership, while valid distinct VLAN units remain independently zoned. The walks allocate only configuration-sized maps/slices, run outside forwarding, and publish immutable snapshots; no lock, leak, integer truncation, cap bypass, or packet-path performance issue was found in this batch.


## A4-b1


Every assigned file was read. Each row records the substantive negative result or the finding association.

| File | Review result |
|---|---|
| `pkg/configstore/activate_test.go` | Candidate-only activate/deactivate mutations preserve idempotence and reject missing paths/out-of-mode calls; no active-policy publication occurs before commit. |
| `pkg/configstore/annotate_lock_5379_test.go` | Annotation holder enforcement is covered; comments cannot mutate another session's candidate through this path. |
| `pkg/configstore/archive_rotate_enoent_4689_test.go` | Concurrent rotation cardinality and benign ENOENT are covered, but it does not exercise zeroize against an outstanding auto-archive goroutine; associated with Finding 1. |
| `pkg/configstore/atomic_load_5187_test.go` | Flat LoadSet/LoadMerge clone before replay and retain the original candidate on a mid-body error; no partial policy edit survives. |
| `pkg/configstore/check.go` | Day-0 text takes the same strict compile pipeline as commit and is size-gated before parse; no alternate permissive policy compiler found. |
| `pkg/configstore/check_test.go` | Positive, parse-error, retired dataplane, schema, node expansion, and node-ID mismatch cases pin strict check behavior; no stale-state mutation occurs. |
| `pkg/configstore/cluster_readonly_3893_test.go` | Open-session mutations and all commit forms are re-gated after demotion; only internal SyncApply/rollback bypass as designed. |
| `pkg/configstore/commit_confirm_demote_4378_test.go` | Demotion cancels the local pending window and stale timer generation; no later local timeout can overwrite the new primary's policy. |
| `pkg/configstore/commit_confirm_pending_edit_4000_test.go` | Explicit confirm versus plain commit semantics preserve or commit staged edits intentionally; no timer reverts the later committed candidate. |
| `pkg/configstore/commit_confirmed_3861_test.go` | Plain commit, HA sync, nested re-arm, and explicit confirmation generation behavior are covered; no new timer-state root found. |
| `pkg/configstore/commit_confirmed_maxrange_4868_test.go` | Duration overflow is bounded at 65535 minutes before persistence/promotion. |
| `pkg/configstore/commit_confirmed_persist_4577_test.go` | Restart re-arm, expired rollback, explicit confirm, and bare-commit permanence are covered. The warn-only WriteConfirm failure is an exact prior `codex-review-175` root and was suppressed. |
| `pkg/configstore/commit_description_cap_4891_test.go` | Oversized audit detail is rejected before commit; defensive UTF-8 truncation keeps journal records below scanner bounds. |
| `pkg/configstore/config_lock_holder_5059_test.go` | Session-scoped candidate mutators reject non-holders; internal empty-session bypass is explicit. |
| `pkg/configstore/config_size_ceiling_hb164_test.go` | Load and HA parse entry points reject payloads above 16 MiB before parser allocation; normal configs remain accepted. |
| `pkg/configstore/configstore_null_decode_5474_test.go` | Top-level null/array/scalar active DB bodies fail closed instead of decoding as empty policy. |
| `pkg/configstore/confirm_delete_fsync_4864_test.go` | confirm.json unlink is followed by parent-dir fsync and absent state avoids a spurious sync; stale recovery intent is not cleanly acknowledged early. |
| `pkg/configstore/confirm_rollback_durable_5473_test.go` | Failed rollback/sync persistence retains confirm.json until the replacement is durable, including post-rename convergence; no new crash window found. |
| `pkg/configstore/crypto.go` | AES-GCM nonce/key generation, nonce-length rejection, HKDF PRF mapping, and durable key-before-ciphertext ordering are sound. Outer committed metadata is not AAD, but this was already noted in `codex-review-179` and requires privileged storage tampering. |
| `pkg/configstore/crypto_envelope_unknown_format_4888_test.go` | Unknown or field-bearing inner envelope formats fail closed and cannot decode as an empty config. |
| `pkg/configstore/crypto_nonce_length_4793_test.go` | Wrong-length nonces return an error rather than panicking the daemon. |
| `pkg/configstore/crypto_prf_sync_4578_test.go` | Advertised schema PRF names and crypto implementations remain synchronized. |
| `pkg/configstore/dataplane_retire.go` | Load/HA compatibility rewrites only the retired selector leaves to userspace and warns; it does not rewrite policy content or broaden an allow/deny. |
| `pkg/configstore/dataplane_retire_test.go` | eBPF/DPDK, groups, split stanzas, userspace no-op, and persisted-load shapes are covered; no missed retired selector path found. |
| `pkg/configstore/db.go` | Active/candidate/rollback writes use durable 0600 atomic files; config bodies require JSON objects; confirm state encrypts from its secret-bearing previous tree. No new transaction or decrypt downgrade root found. |
| `pkg/configstore/db_test.go` | Plain/encrypted round trips and deliberate plaintext rewrite after master-password removal are covered. |
| `pkg/configstore/durability_3441_test.go` | Archive capture/uniqueness, rollback slot-1 durability, degraded reporting, tombstones, and cleanup continuation are covered. Outstanding archive lifecycle during zeroize is absent; associated with Finding 1. |
| `pkg/configstore/envelope.go` | Too-new/malformed compatibility headers fail closed; missing committed marker defaults true for migration. No policy-empty fallback found. |
| `pkg/configstore/envelope_test.go` | Current, legacy, too-new, corrupt, and old-reader rejection paths are covered. |
| `pkg/configstore/equal_flow_worker_cap_test.go` | Removed legacy worker cap stays accepted on strict commit and lenient load/sync; no current allow/deny or resource cap regression. |
| `pkg/configstore/factory_reset.go` | Key-first DB erasure and directory fsyncs are ordered, but archive erasure has no coordination with commit-spawned writers; Finding 1. |
| `pkg/configstore/factory_reset_4858_test.go` | SSOT, journal, rescue, rollback, and key artifacts are covered for a quiescent store; no outstanding-writer case. |
| `pkg/configstore/factory_reset_archive_5186_test.go` | Quiescent default archive deletion, custom-path ownership, sync/remove errors, and absence are covered; it misses delayed recreation and maps directly to Finding 1. |
| `pkg/configstore/factory_reset_durable_5197_test.go` | Key unlink precedes ciphertext removal and both key-dir/final-dir fsync failures propagate. |
| `pkg/configstore/factory_reset_temp_5475_test.go` | Top-level fsatomic crash temps are recognized and erased; pattern scope is bounded to the owned config directory. |
| `pkg/configstore/file_perms_4056_test.go` | Active DB, rollback, rescue, journal, and archives are 0600. Plaintext text copies under master-password are an exact prior `codex-review-175` root, not re-filed. |
| `pkg/configstore/freetext_store_test.go` | Strict commit rejects control-character injection; lenient persisted/HA paths sanitize before active publication. |
| `pkg/configstore/history.go` | Fixed-size ring indexing and bounds are correct for wrap and most-recent-first retrieval; callers serialize access through Store.mu. |
| `pkg/configstore/inactive_test.go` | Inactive apply-groups are stripped before expansion and flat/hierarchical round trips preserve state; inactive policy cannot unexpectedly become active here. |
| `pkg/configstore/journal/journal.go` | Tail work and line assembly are bounded, writes are mutex-serialized, and fsync is off-lock. Append-through-symlink is the exact prior `codex-review-179` finding and was suppressed. |
| `pkg/configstore/journal/journal_test.go` | Rotation, corrupt/torn lines, chunk boundaries, permissions, bounded scans, concurrent log/tail, and slow-fsync races are broad; race test passed. |
| `pkg/configstore/journal_compat_test.go` | Legacy decode, compact records, config hashes, and rollback-file correlation are covered; audit data does not drive policy admission. |
| `pkg/configstore/load_compile_fail_test.go` | Present-but-uncompilable active DB retains recovery tree/history while returning ErrConfigCompile and nil compiled policy, enabling bootstrap/lifeline fail-closed behavior. |
| `pkg/configstore/marker_test.go` | Never-committed versus committed-empty survives first rollback, failed persistence retry, and restart; empty config does not accidentally claim normal boot. |
| `pkg/configstore/masterpw_apply_groups_5231_test.go` | Applied and wildcard group master-password leaves trigger encryption; defined-but-unused groups conservatively over-encrypt. |
| `pkg/configstore/masterpw_split_system_4705_test.go` | All top-level system stanzas participate in the encryption gate and plaintext downgrade warning. |
| `pkg/configstore/nodeid_lenient_test.go` | Lenient load warns rather than blackouts on mismatch; strict commit rejects it. Runtime identity risk is explicit and not a policy permit introduced by configstore. |
| `pkg/configstore/persist_failure_test.go` | Pre-rename commit failure is non-mutating, HA/rollback Option-B degradation is visible and singleton-retried, nested confirm target and stale generation are covered. |
| `pkg/configstore/plaintext_downgrade_warn_4579_test.go` | Unexpected plaintext under master-password is observable but accepted for compatibility; this behavior and text-copy exposure are prior roots, not duplicated. |
| `pkg/configstore/postrename_dbboundary_5234_test.go` | Real DB wrapping preserves PostRenameSyncError classification and convergence to the visible candidate. |
| `pkg/configstore/postrename_durability_5185_test.go` | Commit and commit-confirmed converge memory to disk-visible C after post-rename fsync failure; pre-rename remains a clean rejection. |
| `pkg/configstore/ra_interval_4525_test.go` | Strict ratio validation rejects unsafe RA intervals; lone/default leaves remain delegated to bounded runtime derivation. |
| `pkg/configstore/redaction_placeholder_4060_test.go` | Strict commit/check reject redaction sentinels as credentials; lenient stored load is compatibility-only and does not manufacture a valid secret. |
| `pkg/configstore/rescue_delete_fsync_5197_test.go` | Rescue unlink durability and absent-state behavior are covered. |
| `pkg/configstore/rescue_redaction_leak_4099_test.go` | Malformed rescue display fails closed with position-only errors and cannot echo secret tokens. |
| `pkg/configstore/rollback_corrupt_log_4690_test.go` | Corrupt rollback diagnostics log path/position without parser token contents; slot tombstoning prevents index shift. |
| `pkg/configstore/store.go` | Strict/lenient boundaries, size cap, HA in-memory promotion, confirm supersession, and retry markers were traced. The downstream stale-policy apply/session-invalidations are existing A7 and `codex-review-176` roots, handed off below. |
| `pkg/configstore/store_command.go` | Every candidate mutator checks writable/holder state and flat bulk loads use clone-then-swap atomicity; no partial candidate publication found. |
| `pkg/configstore/store_commit.go` | Persist-before-promote and confirm generation logic are sound, but untracked auto-archive goroutines cross zeroize; Finding 1. |
| `pkg/configstore/store_format.go` | Read methods lock and clone where ownership requires it; redacted variants cover active/candidate/rollback output. No mutation or enforcement divergence found. |
| `pkg/configstore/store_lock.go` | Store.mu serializes holder/lease state, stale lock reclamation is bounded, and cluster read-only is checked again by mutators. |
| `pkg/configstore/store_lock_3979_test.go` | Exclusive lock release/reacquire and live-holder blocking are covered. |
| `pkg/configstore/store_lock_lease_4476_test.go` | Shared/exclusive stale leases reclaim while active/reentrant use refreshes; no permanent lock resource leak found. |
| `pkg/configstore/store_new_test.go` | An unusable DB directory aborts construction; no nil/file fallback can later lose policy persistence. |
| `pkg/configstore/store_persist.go` | Load fail-closed sentinels, durable writes/deletes, bounded retry, archive creation/rotation, and rescue redaction were traced. `writeArchive` recreates the wiped path; Finding 1. |
| `pkg/configstore/store_test.go` | Broad strict compile, commit/rollback/timer, persistence, display, load, rescue/archive, locking, edit, and retired-dataplane coverage passed; the known giant-test modularity root is deduplicated. |
| `pkg/configstore/system_action_journal_4108_test.go` | Destructive action journal records are durable metadata and excluded from commit history; journal failure is intentionally non-blocking. |
| `pkg/configstore/test_seams.go` | Seams are mutex-protected and test-only; the overlay probe used package-local access without changing production files. |
| `pkg/configstore/typed_leaf_lenient_test.go` | Strict operator commits reject malformed typed/reference leaves while load/sync tolerate legacy shapes. Existing compiler/runtime fail-closed backstops own any lossy lenient policy semantics; no new configstore root found. |


## A5-b1


- `pkg/cluster/cluster_test.go` — cluster orchestration; exercised election, readiness, manual/batch transfer, fencing, status and event-drop paths. Negative: no additional root beyond A5-Z5-01; transfer tests omit applied-config convergence.
- `pkg/cluster/controllink_auth_status_4484_test.go` — auth observability; authenticated/dual-accept display is covered; no secret disclosure or false status found.
- `pkg/cluster/election.go` — HA election; checked duplicate IDs, preempt/non-preempt, manual/kernel holds, peer loss, readiness and tie breaks; no dual-primary or false-deny root found.
- `pkg/cluster/election_dup_nodeid_4549_test.go` — duplicate-node hostile cases; both preempt and dual-active yield safely.
- `pkg/cluster/election_test.go` — election matrix and timer readiness; peer-loss bypass is deliberate availability behavior, with no new policy-session defect.
- `pkg/cluster/events.go` — bounded history concurrency/resource lifetime; copies and ring replacement are sound.
- `pkg/cluster/events_log.go` — slog adapter; no mutable/shared-state or security behavior.
- `pkg/cluster/events_test.go` — history wrap/isolation/concurrency; substantive negative coverage.
- `pkg/cluster/failover.go` — planned failover lifecycle; checked prepare, request/ack, local commit, peer finalization, rollback and grace overrides; A5-Z5-01 reaches this gate.
- `pkg/cluster/failover_races_5245_5246_test.go` — group-removal timer and reset/pre-hook races; stale callbacks and clobber are covered.
- `pkg/cluster/garp.go` — ARP/NA serialization, checksum, socket lifetime and burst predicates; bounded follow-ups abort on abdication.
- `pkg/cluster/garp_abdicate_test.go` — epoch/master gates for IPv4/6 follow-ups; no post-demotion advertisements.
- `pkg/cluster/garp_burst_errors_test.go` — error counters; partial burst failures remain observable.
- `pkg/cluster/garp_test.go` — packet wire checks, source selection and family rejection; no malformed-frame or endian issue.
- `pkg/cluster/group_state.go` — config-to-runtime RG publication and snapshots; removal stops timers and status copies slices; no torn ownership view.
- `pkg/cluster/heartbeat.go` — parse/auth/replay/liveness; lengths are bounded, HMAC downgrade guard is sticky after authentication, monotonic timeout logic is sound.
- `pkg/cluster/heartbeat_auth_test.go` — tamper, replay, key mismatch and downgrade decision matrix covered.
- `pkg/cluster/heartbeat_family_4549_test.go` — IPv4/IPv6 socket-family parity; no family-specific liveness gap.
- `pkg/cluster/heartbeat_guard_recheck_test.go` — late heartbeat guard recheck; avoids stale timeout promotion.
- `pkg/cluster/heartbeat_liveness_test.go` — monotonic age/restart grace; no wall-clock regression.
- `pkg/cluster/heartbeat_manager.go` — socket start/restart, heartbeat construction and peer handling; previous workers are joined and wire-width caps honored.
- `pkg/cluster/heartbeat_neverseen_floor_test.go` — cold-boot floor; never-seen peer cannot trigger premature promotion.
- `pkg/cluster/heartbeat_rg_cap_4434_test.go` — oversized RG list truncates consistently without panic or count/body mismatch.
- `pkg/cluster/heartbeat_stop_previous_test.go` — idempotent replacement; no duplicate sender/receiver lifetime.
- `pkg/cluster/heartbeat_test.go` — malformed/truncated/versioned heartbeat and monitor payloads covered; no fail-open parse.
- `pkg/cluster/hooks.go` — callback publication under manager lock; no unguarded callback race found.
- `pkg/cluster/kernel_selfrecover.go` — upgrade hold/rejoin facts; isolated candidate remains held and reset re-elects correctly.
- `pkg/cluster/lease_sync_wire_test.go` — bounded DHCP lease decode and aging; huge count does not overallocate.
- `pkg/cluster/manager.go` — manager lifecycle, event channel and shared state; stop cancels hold timers; callback calls checked for lock inversions.
- `pkg/cluster/manager_start_deadlock_test.go` — monitor replacement AB/BA regression covered.
- `pkg/cluster/manager_stop_test.go` — stopped-manager timer suppression covered.
- `pkg/cluster/monitor.go` — interface/IP probing, dampening and netlink handle lifetime; reply tuple validation and carrier state are enforced.
- `pkg/cluster/monitor_test.go` — IPv4/6 probe, stale sequence, flap and concurrent status tests; no false-ready path found.
- `pkg/cluster/peer_state.go` — peer snapshots/auth/version facts; copies and unknown-version behavior are safe.
- `pkg/cluster/readiness.go` — takeover readiness timer publication; generation/stopped/group-presence guards prevent stale promotion.
- `pkg/cluster/reth.go` — RETH mapping/MAC/link-local helpers; member activation is RG-filtered; errors are availability-only and not policy authorization.
- `pkg/cluster/reth_test.go` — deterministic identity and RG filtering covered.
- `pkg/cluster/runtime.go` — narrow session-store/telemetry boundary; no legacy dataplane escape.
- `pkg/cluster/status.go` — HA/session/auth/readiness counters and API parity; config apply failures are visible but do not gate transfer (A5-Z5-01).
- `pkg/cluster/sync.go` — wire model/stats/readiness state; policy ID/counter/app timeout/NAT64 metadata present, but no applied-config epoch in transfer readiness (A5-Z5-01).
- `pkg/cluster/sync_accept_test.go` — handshake timeout and accept-loop isolation; slow hostile connection cannot block others.
- `pkg/cluster/sync_auth.go` — challenge/proof/frame MAC/replay; bounds and key erasure paths checked, no new bypass beyond documented rolling dual-accept.
- `pkg/cluster/sync_auth_test.go` — keyed, mismatch, downgrade, disabled and replay cases covered.
- `pkg/cluster/sync_bulk.go` — bulk marker ordering, snapshot reconciliation, ack/barrier waits; session completeness is tracked, config completeness is not (A5-Z5-01).
- `pkg/cluster/sync_config_gen_test.go` — ordered config tests; proves lower generation admission after session bulk reset and lacks failover-readiness integration (A5-Z5-01).
- `pkg/cluster/sync_conn.go` — install/delete generations, queue/journal, config consumer, dual fabric and message dispatch; root evidence for A5-Z5-01.
- `pkg/cluster/sync_failover.go` — request IDs, waiter overlap, ack/commit and disconnect cleanup; no stale-ack takeover found, but callers trust incomplete readiness.
- `pkg/cluster/sync_gen_guard_test.go` — v4/6 stale install/delete, tombstone, cap, reboot and policy metadata wire coverage; no cross-config authorization epoch test.
- `pkg/cluster/sync_protocol.go` — length-gated v4/6, config, failover, lease and NAT64 codecs; checked integer/length bounds and byte order.
- `pkg/cluster/sync_state.go` — sync-ready/transport/stats accessors; lock discipline sound, readiness semantics inherit A5-Z5-01.
- `pkg/cluster/sync_test.go` — sync serialization, bulk, journals, barriers, failover, liveness and dual-fabric tests; comprehensive session transport coverage, missing config-vs-transfer invariant.
- `pkg/cluster/upgrade_drain.go` — observed all-RG peer-primary drain fence; no desired-state-only success.
- `pkg/cluster/upgrade_drain_test.go` — partial/missing/dead peer and disabled-RG drain cases covered.
- `pkg/conntrack/gc.go` — session expiry/count hot path; scratch reuse, secondary retention, partial-delete callbacks and locked config snapshots are sound.
- `pkg/conntrack/gc_test.go` — v4/6 partial progress, aggressive aging, backoff and race coverage; no standby premature expiry.
- `pkg/conntrack/legacy_dataplane_canary_test.go` — AST canary closes legacy type aliases/interface-method bypasses.
- `pkg/ra/config_removal_goodbye_5092_test.go` — all/one-interface removal emits final lifetime-zero RA; config changes avoid false withdrawal.
- `pkg/ra/filter.go` — ICMPv6 RS filter construction is minimal and correct.
- `pkg/ra/goodbye_failure_5093_test.go` — terminal write failures are surfaced, not falsely acknowledged.
- `pkg/ra/per_iface_epoch_4961_test.go` — unrelated interface operations do not supersede each other.
- `pkg/ra/ra.go` — manager apply/withdraw/clear ownership, tombstones and reclaimer; joins are outside locks and owed actions survive timeout.
- `pkg/ra/ra_test.go` — RA options/lifetimes/config equality and malformed prefixes covered.
- `pkg/ra/reclaimer_sender_5094_test.go` — deferred restart/goodbye survives late owner exit.
- `pkg/ra/rs_receive_validation_5095_test.go` — hop-limit/source validation blocks off-link RS-triggered amplification.
- `pkg/ra/sender.go` — socket setup, RS receive, interval, RA marshal and link-local creation; intervals are clamped and malformed options pruned.
- `pkg/ra/sender_interval_4525_test.go` — no zero-duration hot loop.
- `pkg/ra/sender_linklocal_test.go` — stable/EUI-64 address generation and no procfs side effects covered.
- `pkg/ra/sender_marshal_3895_test.go` — oversized malformed option drops without losing valid options.
- `pkg/ra/sender_marshal_4119_test.go` — explicit/unset router lifetime parity covered.
- `pkg/ra/sender_marshal_4307_test.go` — reachable/retransmit timers survive wire encoding.
- `pkg/ra/serialize_test.go` — exhaustive sender ownership, shutdown ordering, lock and live-connection invariant; no incoherent overlap found.
- `pkg/ra/timer_leak_4830_test.go` — timer allocation/leak guard and fast path covered.
- `pkg/vrrp/addrwatch.go` — address watcher uses ifindex/name recovery and reconcile scheduling; bounded singleton lifecycle.
- `pkg/vrrp/addrwatch_test.go` — rename/recreate/late-interface and unrelated-event cases covered.
- `pkg/vrrp/afpacket_cloexec_test.go` — raw socket close-on-exec verified.
- `pkg/vrrp/afpacket_membership_test.go` — all-multicast membership avoids promiscuous mode; multicast MACs correct.
- `pkg/vrrp/bindtodevice_test.go` — VLAN bind-to-device gate matches receiver call site.
- `pkg/vrrp/instance.go` — VRRP state machine, raw RX, preempt hold, GARP/NA and source locking; wire validation, ifindex, hop-limit and epoch gates checked.
- `pkg/vrrp/instance_arp_probe_test.go` — VIP sender and gateway skip behavior covered.
- `pkg/vrrp/instance_garp_abdicate_test.go` — no GARP after master loss.
- `pkg/vrrp/instance_garp_force_test.go` — forced reconciliation bypasses dampening but not epoch/master invariants.
- `pkg/vrrp/instance_garp_probe_target_test.go` — subnet-correct gateway target, including long prefixes.
- `pkg/vrrp/instance_garp_test.go` — dampening regression covered.
- `pkg/vrrp/instance_ifindex_filter_test.go` — cross-VLAN/cross-interface advertisements rejected for IPv4/6.
- `pkg/vrrp/instance_localip_race_test.go` — lazy source resolution is race-safe.
- `pkg/vrrp/instance_master_interval_test.go` — centisecond conversion, low floors, zero/priority-zero and slower-master behavior covered.
- `pkg/vrrp/instance_owner_preempt_test.go` — owner priority semantics and non-owner no-preempt denial covered.
- `pkg/vrrp/instance_preempt_gate_test.go` — live/stale/equal master and force gates covered; denied preemption leaves watchdog armed.
- `pkg/vrrp/instance_preempt_hold_revalidate_test.go` — config/priority changes revalidated at hold expiry.
- `pkg/vrrp/instance_preempt_hold_watchdog_test.go` — dead held master bypasses hold; live master does not.
- `pkg/vrrp/instance_preempt_holdtime_test.go` — return/resign/stale master transitions covered.
- `pkg/vrrp/instance_rxdrop_race_test.go` — warning dampener atomicity and reset covered.
- `pkg/vrrp/instance_v6_hoplimit_test.go` — non-255 IPv6 VRRP rejected.
- `pkg/vrrp/instance_v6_pktinfo_test.go` — IPv6 source/ifindex pinned in control message.
- `pkg/vrrp/instance_vipset_canon_test.go` — canonical VIP exclusion prevents selecting virtual source as local identity.
- `pkg/vrrp/manager.go` — build-before-teardown instance reconcile, sync hold, watcher and event lifecycle; invalid VRID is skipped at runtime.
- `pkg/vrrp/manager_garp_unsuppress_test.go` — unsuppression forces one master-only burst.
- `pkg/vrrp/manager_reuse_test.go` — Stop/Start channels/watchers/context are refreshed.
- `pkg/vrrp/packet.go` — VRRPv3 marshal/parse checks version, count, addresses and IPv4/6 pseudo-header checksums.
- `pkg/vrrp/packet_checksum_test.go` — RFC checksum vectors, corruption rejection and bounded legacy acceptance covered.
- `pkg/vrrp/track.go` — singleton link watcher/poller and priority demotion; rename cache handles stale names.
- `pkg/vrrp/track_test.go` — update, rename, subscription fallback and no-track negative cases covered.
- `pkg/vrrp/update_instances_test.go` — socket proof before old teardown; transient failure keeps old forwarding instance.
- `pkg/vrrp/vrid_guard_4573_test.go` — reserved/overflow VRID runtime guard and boundaries covered.
- `pkg/vrrp/vrrp.go` — config collection, VLAN/RETH identity and direct-mode exclusion; derived VRID strict/lenient contract checked against config validators.
- `pkg/vrrp/vrrp_test.go` — collection, parse, sync hold, tie-break, AF_PACKET VLAN/QinQ/ext-header and event-drop matrix; no additional HA defect.


## A6-b1


### Compiler, lowering, and application identity

- `pkg/dataplane/appid_catalog_parity_test.go` — application ID/name parity across malformed destination/source ports, tolerant load, multi-term expansion, and overflow was inspected; tests substantively pin that malformed applications never receive a helper-resolvable identity. No novel widening survived.
- `pkg/dataplane/appid_catalog_port_zero_5194_test.go` — port-zero sentinel behavior was inspected; zero-port malformed applications remain absent from the live catalog rather than becoming wildcard applications.
- `pkg/dataplane/compiler.go` — compile phase order, stable zone IDs, address books, applications/app sets, zone/global/default policy metadata, scheduler slots, flow configuration, interface tuning, and mirror lowering were traced. The live userspace path consumes only metadata and separately builds the enforcement snapshot; legacy map writes are suppressed. Undefined/malformed app-to-any behavior in the retired projection is guarded by strict validation and live snapshot integrity checks; no new active fail-open was retained.
- `pkg/dataplane/compiler_filter.go` — inet/inet6 filter expansion, protocol/ports/ICMP-adjacent fields, prefix-list negation, term order/actions, counters, policers, lo0/interface bindings, integer bounds, and cross-product cap were inspected. This is a retired eBPF projection; the cap prevents unbounded allocation and active userspace filters are lowered separately. No novel contract drift survived.
- `pkg/dataplane/compiler_filter_expansion_5456_test.go` — oversized cross-product clamping and uint32 safety were inspected; it pins bounded retired-path allocation.
- `pkg/dataplane/compiler_filter_expansion_test.go` — expansion stride/count agreement and filter-rule limits were inspected; substantive negative coverage is present.
- `pkg/dataplane/compiler_filter_protocol_test.go` — named/numeric protocol resolution and unknown-protocol handling were inspected; protocol zero is not silently stamped as a restrictive match.
- `pkg/dataplane/compiler_iface.go` — logical/physical/VLAN/RETH identity, interface-zone assignments, host-inbound metadata, screen references/defaults, tunnel handling, and userspace attachment planning were traced for v4/v6. Active snapshot builders re-resolve enforcement identity; no assigned-file mismatch survived cross-checking.
- `pkg/dataplane/compiler_nat.go` — SNAT/DNAT/static/NPTv6/NAT64 phase order, zone scope, addresses, interface mode, ports, pool bounds, counter identities, byte order, and stale cleanup were inspected. Authoritative userspace counter IDs are finalized after all NAT classes in deterministic key order; vestigial u16 stamps are not consumed live. No novel NAT widening survived.
- `pkg/dataplane/compiler_nat_counter_collision_test.go` — SNAT/DNAT/static type namespace collision coverage was inspected; identities remain disjoint.
- `pkg/dataplane/compiler_nat_counter_determinism_test.go` — sorted collision resolution and order independence were inspected; cumulative helper counters cannot swap solely from traversal reorder.
- `pkg/dataplane/compiler_nat_counter_stability_test.go` — add/remove/reorder stability and zero sentinel behavior were inspected; substantive regression coverage is present.
- `pkg/dataplane/compiler_test.go` — policy expansion boundaries/scheduler slots, screen defaults, flow values, parser edges, interface behavior, and NAT helpers were inspected. Tests cover exact-cap positive and over-cap negative behavior; no missing active-policy assertion yielded a novel finding.
- `pkg/dataplane/nptv6_test.go` — RFC 6296 adjustment, family/prefix validation, stale rules, and map projection were inspected; active enforcement is snapshot-owned and no arithmetic/endianness defect survived.
- `pkg/dataplane/pci_function_suffix_4795_test.go` — PCI multifunction suffix construction and bounds were inspected; interface identity does not alias functions.
- `pkg/dataplane/zoneid_stable_test.go` — stable name-derived zone identity across reorder/addition was inspected; IDs avoid reserved host/global values and remain suitable for snapshot/counter identity.

### Runtime apply boundary, publication, and retirement

- `pkg/dataplane/apply.go` — `RuntimeDataPlane`, apply-result cloning/generation, context checks, link/HA/telemetry adapters, and error propagation were inspected. Mutable maps/slices are cloned before publication to readers; the legacy `Manager.ApplyConfig` is unreachable for the default userspace backend.
- `pkg/dataplane/apply_test.go` — display metadata, clone isolation, backend-neutral contract size, operator-surface migration, and pre-canceled apply were inspected; publication metadata is not aliased.
- `pkg/dataplane/dataplane.go` — backend selection, empty-default userspace resolution, retired eBPF/DPDK rejection, runtime registration, and the legacy `DataPlane` ABI were inspected. Unknown/retired types fail closed and cannot silently resurrect an old forwarding backend.
- `pkg/dataplane/default_test.go` — default runtime backend selection was inspected; omitted type resolves only to userspace.
- `pkg/dataplane/loader.go` — shim load/compile entry points, XDP attachment, preflight interface cap, stale legacy pin/link cleanup, map/program ownership, and the no-op `userspaceShimCompileDataplane` compatibility adapter were traced. The no-op setters are retired generated-projection residue, not the live policy/filter/screen publication path. The `dnat_table_v6` preflight inventory omission is duplicate-suppressed below.
- `pkg/dataplane/loader_userspace_shim.go` — Go-created shared maps, Rust collection replacements, pin lifetimes, live-pin ABI comparison, disposable-map migration, and expected shape checks were inspected. Shared-map handles close on every failed load path. The missing v6 expected/live ABI gate is prior campaign finding `A6-b3-F004`, not re-reported.
- `pkg/dataplane/legacy_bpf_manifest_canary_test.go` — tracked generated/source manifest completeness, retained shim exclusions, and dependency order were inspected; it prevents accidental removal or resurrection across the old-helper boundary.
- `pkg/dataplane/retirement_boundary_canary_test.go` — legacy imports, manager methods, map/program inventories, arbitrary XDP swap escape paths, JSON/reflection/method-value bypasses, runtime constructors, and documentation assumptions were inspected. The AST canary is broad and startup-only; no packet hot-path cost applies.
- `pkg/dataplane/runtime/import_canary_test.go` — forbidden legacy backend imports were inspected; runtime package boundaries remain userspace-only.
- `pkg/dataplane/userspace_shim_loader_test.go` — embedded object, expected/live ABI drift, unreadable pins, disposable counter migration, legacy cleanup, and replacement refusal tests were inspected. Coverage notably tests expected shape only for v4 DNAT; that exact v6 gap is already owned by `A6-b3-F004`.
- `pkg/dataplane/userspace_xdp_rust.go` — generated embedded-object binding was inspected; it contains no policy logic or mutable state and is consumed through the validated loader.
- `pkg/dataplane/verify_userspace_shim.go` — candidate parsing, production spec validation, verifier-only copied-spec shrinking, verifier diagnostics, and collection lifetime were inspected. Validation precedes mutation and anonymous verifier maps close deterministically.
- `pkg/dataplane/verify_userspace_shim_test.go` — malformed object, verifier error, shrink equivalence, and production-gate reuse were inspected; kernel/root-dependent cases are explicitly gated.
- `pkg/dataplane/watchdog_test.go` — HA watchdog map update behavior was inspected; index/value width matches the shared map ABI.

### Shared map ABI, counters, sessions, and state

- `pkg/dataplane/bpf_session_value.go` — v4/v6 typed-to-wire projection was checked field-for-field against `SessionValue`, C/Rust sizes, byte order, and sync-only exclusions. `Generation`, `PolicyCounterIdx`, and `Nat64SnatV4` remain off-map by design; map IO uses 128/176-byte dedicated types.
- `pkg/dataplane/bpf_session_value_test.go` — C/Rust ABI sizes, registered map sizes, round trips, and sync-only field loss were inspected; it pins the OOB-prevention contract.
- `pkg/dataplane/constants.go` — interface/queue capacity constants were inspected against flattened binding dimensions; arithmetic is compile-time bounded.
- `pkg/dataplane/constants_test.go` — ifindex lower/upper bounds, netlink preflight behavior, and C-header parity were inspected; invalid indices are rejected before map/index use.
- `pkg/dataplane/cpumask.go` — online CPU mask parsing, range expansion, bounds, and dedup were inspected; work is startup-only and bounded by host CPU inventory.
- `pkg/dataplane/cpumask_test.go` — valid/range/malformed CPU-list coverage was inspected; parser errors do not fabricate CPUs.
- `pkg/dataplane/current_sessions_test.go` — saturating active-session arithmetic was inspected; close-before-create races cannot underflow to a huge count.
- `pkg/dataplane/maps_counters.go` — global/interface/zone aggregation, sparse stable-zone offsets, clear orchestration, map absence, per-CPU slices, and locks were inspected. Stable hashed zone IDs never index dense legacy arrays on reads; unavailable counters are distinct from zero and read errors.
- `pkg/dataplane/maps_fabric.go` — fabric/HA map writes and FIB generation publication were inspected; the bump writes the new generation before returning and reports update failure.
- `pkg/dataplane/maps_filter.go` — retired filter/config/policer writes, per-CPU reads, and clears were inspected. Ignored per-slot clear errors remain on retired enforcement maps and do not affect the live helper path.
- `pkg/dataplane/maps_flow.go` — flow timeout/config writes and lo0 sentinel widths were inspected; active userspace flow state comes from the snapshot.
- `pkg/dataplane/maps_helpers.go` — host/network byte-order and IP conversion helpers were inspected at NAT/session callers; v4 addresses and ports use the consumer-expected encodings.
- `pkg/dataplane/maps_mirror.go` — mirror map set/clear behavior was inspected; this is retired map residue and has no live userspace packet-path ownership.
- `pkg/dataplane/maps_nat.go` — NAT map access, static/dynamic separation, v4/v6 key/value encoding, counter offsets, and clear behavior were inspected. Helper cumulative totals overwrite offsets under the manager lock; counter key identities are u32 and type-namespaced above.
- `pkg/dataplane/maps_policy.go` — retired zone/policy/address/application/default writes, scheduler slots, counters, and clear behavior were inspected. Active userspace policy is not read from these maps; unknown scheduler defaults in this dead path cannot widen live enforcement.
- `pkg/dataplane/maps_screen.go` — screen/session-limit map writes, sparse flood offsets, and clear behavior were inspected. Live screen enforcement is snapshot-owned; absent counters return `ErrCounterNotPopulated` rather than a false zero.
- `pkg/dataplane/maps_session.go` — v4/v6 conntrack map IO, batch iteration/delete, bounded full clears, dynamic DNAT companions, yields, counts, and map ABI types were inspected. Full clears cap working memory and active userspace wrappers send every collected key to the authoritative helper.
- `pkg/dataplane/maps_session_clear_test.go` — batch-delete fallback, bounded chunk snapshots, all-key/DNAT cleanup, and observer coverage were inspected; supported-max clear does not allocate an entire table snapshot.
- `pkg/dataplane/maps_stale.go` — stale hash deletes and array zeroing for policy/NAT/screen/filter state were inspected. Methods are retained legacy cleanup; iteration errors/void returns do not govern live snapshot publication.
- `pkg/dataplane/maps_stats.go` — map inventory, countability, info reads, and sparse iteration were inspected; arrays are not misreported as fully utilized live entries.
- `pkg/dataplane/maps_stats_test.go` — descriptor names/countability and stale-name rejection were inspected; operator map statistics match retained map identities.
- `pkg/dataplane/screen_reason_counters_3343_test.go` — Go global indices, Rust status ordinal names, and count were inspected; all 14 reason identities align.
- `pkg/dataplane/session_store.go` — HA peer install, forward/reverse/DNAT companion transaction and rollback, batch invalidation, persistent-NAT preservation, cluster stale reconciliation, and v4/v6 byte order were inspected. The apparent BPF partial-batch-delete remainder issue is refuted for security enforcement because the active userspace adapter authoritatively deletes every submitted key from the helper regardless of mirror result; it remains no novel campaign finding.
- `pkg/dataplane/session_store_test.go` — transaction rollback, companion creation/deletion, error injection, persistent NAT, bulk reconcile, and nil behavior were inspected; active helper routing was cross-checked outside batch.
- `pkg/dataplane/runtime/session_delta.go` — backend-neutral session delta DTO/source shape was inspected; immutable value transport has no publication side effect.
- `pkg/dataplane/types.go` — all shared structs/constants were checked for field width, padding, sentinels, policy/NAT/filter/screen/counter identities, event layout, v4/v6 parity, and sync-only annotations. No narrowing/alias collision survived existing boundary tests.
- `pkg/dataplane/zone_flood_counters_hide_test.go` — unavailable zone/flood counters versus zero/error rendering were inspected; false observability claims are prevented.

### Persistent NAT and proxy neighbor state

- `pkg/dataplane/persistent_nat.go` — binding key, pool lookup, expiration, save/GC/clear locking, permit modes, and snapshot copies were inspected. `All` deep-copies value-only bindings; no live pointer escapes the lock.
- `pkg/dataplane/persistent_nat_test.go` — lookup/expiration/pool mapping/permit, mutation isolation, and race-oriented snapshot coverage were inspected; returned snapshots remain immutable during concurrent saves.
- `pkg/dataplane/protected_iface_test.go` — protected management/interface exclusion behavior was inspected; no accidental shim attachment to protected interfaces is admitted.
- `pkg/dataplane/proxyarp.go` — desired/existing v4/v6 NTF_PROXY reconciliation, VLAN interface identity, prior-interface orphan sweep, sysctl enable/disable handoff, partial add failure, and GARP family gating were inspected. The documented broad IPv4 kernel `proxy_arp` behavior is tracked under prior #2197 and is not duplicated.
- `pkg/dataplane/proxyarp_orphan_4955_test.go` — prior-interface removal sweep and remembered-state preservation on add failure were inspected; stale responders are not forgotten.
- `pkg/dataplane/proxyarp_test.go` — v4/v6 family correctness, add/remove, mapped-v4, sysctl order/failure, and nil config were inspected; substantive positive/negative coverage is present.

### Typed-to-wire, compatibility, and publication handoffs

- Live ABI versus generated compatibility versus retired residue: the daemon selects `pkg/dataplane/userspace.Manager` through `RuntimeDataPlane`; `CompileUserspaceShim` invokes the shared compiler only for Linux attachment planning and display metadata; its map setters are intentionally no-op. Enforcement is rebuilt into `ConfigSnapshot` outside this batch and published by `apply_snapshot`. Retained live kernel ABI consists of the Rust shim maps plus Go-created shared session/DNAT/counter/fabric maps. The legacy `DataPlane` policy/filter/screen/NAT setter surface and `maps_{policy,filter,screen,stale}` implementations are retired residue, guarded by retirement canaries.
- Typed-to-wire ledger: `SessionValue{,V6}` projects to `bpfSessionValue{,V6}` with exact 128/176-byte C/Rust layouts; sync-only HA fields remain on the cluster wire only. DNAT v4/v6 keys use host-order numeric ports at the shim boundary; NAT counter IDs use stable u32 typed keys in the snapshot/status bridge; screen reason ordinal/index/name identity is pinned by `screen_reason_counters_3343_test.go`; zone counters use sparse stable IDs rather than dense map indices.
- Compatibility matrix: current helper/current Go is covered by embedded-object and package tests; old pinned data maps are preserved and incompatible data pins are refused; the disposable degraded-path counter alone may be recreated; old eBPF/DPDK backends are rejected; old-helper snapshot feature gates are owned by userspace manager/protocol code. Duplicate handoff to Z7: `dnat_table_v6` is omitted from `userspacePinnedShimMaps` and fresh-node expected-shape checks, exactly prior `A6-b3-F004`.
- Transactional publication trace: daemon `ApplyConfig` -> userspace `Compile` -> assigned `CompileUserspaceShim` attachment/metadata pass -> out-of-batch immutable snapshot build -> classifier/bootstrap fail-closed sync -> helper protocol/unsupported gates -> `apply_snapshot` -> advance `lastSnapshot`, published generation/hash, HA/forwarding state, and `ApplyResult`. Build/publish failure retains previous-good helper policy, but attachment/bootstrap side effects before helper publication are a known cross-owner planning/actuation boundary already tracked as prior `R6B2-01/R6B2-02`; handed to Z2 without duplication.
- Counter identity handoff: compiler NAT IDs are stable across reorder and namespace NAT type; policy IDs/default sentinel and screen ordinals match userspace consumers; zone/flood unavailable state is explicit. The active helper owns cumulative policy/NAT/screen values and clear IPC durability outside this batch; no identity split was found here.


## A6-b2


### Policy, address-book, application, default-policy, and snapshot construction

- `pkg/dataplane/userspace/address_book_collision_2514_test.go` — collision error propagation; checked panic avoidance, folded-hash collision rejection, and prior-state retention coverage; no new issue.
- `pkg/dataplane/userspace/address_book_test.go` — address-book IDs/content dedup; checked deterministic IDs, IPv4/IPv6 normalization, `any`, literals, and policy book references; no new issue.
- `pkg/dataplane/userspace/addressbook_slash_name_4340_test.go` — slash-bearing names; checked name-before-literal resolution and prefix emission; no new issue.
- `pkg/dataplane/userspace/app_catalog_test.go` — AppID catalog wire shape; checked build, JSON round trip, empty omission, and ID/name agreement; no new issue.
- `pkg/dataplane/userspace/app_inactivity_timeout_3227_test.go` — application timeout lowering; checked positive/default/negative values and u32 coercion; no new issue.
- `pkg/dataplane/userspace/app_inactivity_timeout_precedence_3298_test.go` — overlapping app/app-set order; checked first-configured precedence and deterministic expansion; no new issue.
- `pkg/dataplane/userspace/app_set_reject_3727_test.go` — malformed app-set tolerant path; checked reserved sentinel and whole-snapshot rejection rather than match-any admission; no new issue.
- `pkg/dataplane/userspace/builder.go` — full snapshot assembly/publication hash; traced zones, interfaces, policies, global/default policy, applications, filters, screens, NAT, routes/PBR, CoS, feeds, HA summary, collision quarantine, and neighbor hash filtering; no new fail-open or partial-build issue.
- `pkg/dataplane/userspace/capabilities.go` — strict/lenient representability and app/address expansion; checked recursive sets, cycles, `any`, protocol/port parsing parity, named ports, ICMP constraints, old-helper canonicalization, and class-(i)/(ii) separation; no new issue.
- `pkg/dataplane/userspace/default_policy_3065_test.go` — implicit default action; checked absent/unknown action fails to deny and explicit permit remains represented; no new issue.
- `pkg/dataplane/userspace/default_policy_counter_3363_test.go` — default-policy counter sentinel; checked read-through identity and no collision with explicit rules; no new issue.
- `pkg/dataplane/userspace/default_policy_log_3534_test.go` — implicit permit logging; checked session-init/close bits reach the snapshot; no new issue.
- `pkg/dataplane/userspace/feed_enforcement_test.go` — feed overlay enforcement; checked direct and destination book references, empty feeds, static union, content hash change, adapter forwarding, and scheduler republish retention; the known nested-feed NAT residual is deduplicated, with no new root.
- `pkg/dataplane/userspace/lenient_keep_armed_3261_test.go` — tolerant-load policy fail-closed behavior; checked unsupported app/address sentinels, feed sets, cycles, empty nested sets, diagnostics, and genuine semantic disarm; no new issue.
- `pkg/dataplane/userspace/manager_capabilities_test.go` — capability gates; checked screens/SYN cookies, policers, mirrors, filters, IPsec/tunnels, flow knobs, HA fabric, persistent SNAT, and protocol gates; no new issue.
- `pkg/dataplane/userspace/manager_policy_test.go` — zone/global policy snapshots and scheduler publication; checked address/app matching, global rules, rule IDs, inactive bits, old helpers, helper absence, and apply response; no new issue.
- `pkg/dataplane/userspace/manager_republish_3780_test.go` — scheduler failure convergence; checked failed publish returns an error and helper absence is a converged no-op; no new issue.
- `pkg/dataplane/userspace/manager_snapshot_test.go` — snapshot equality, summary, policy-rule count, and content hash; checked volatile exclusion versus forwarding-content sensitivity; no new issue.
- `pkg/dataplane/userspace/named_port_caseinsensitive_3372_test.go` — mixed-case service names; checked compile/apply parity and absence of unsupported sentinels; no new issue.

### NAT, routing/PBR, flow, filters, screens, CoS, and counters

- `pkg/dataplane/userspace/applied_nat_view.go` — applied-generation NAT status view; checked config/counter generation pairing, deferred workers, dedup, lock scope, helper availability, and FIB-only changes; no new issue.
- `pkg/dataplane/userspace/applied_nat_view_test.go` — NAT view tests; checked unavailable, coherent/mid-apply, FIB bump, deferred apply, generation zero, and shared-pool dedup cases; no gap promoted.
- `pkg/dataplane/userspace/cos.go` — CoS snapshot lowering; checked undefined references, safe defaults, queues, classifiers/rewrites, scheduler maps, exact/surplus/equal-flow fields, sorting, and lenient degradation; no new packet-admission issue.
- `pkg/dataplane/userspace/cos_iface_level_4021_test.go` — interface-level CoS precedence; checked parsed configuration reaches logical interface snapshots; no new issue.
- `pkg/dataplane/userspace/fbf_snapshot_test.go` — filter-based forwarding; checked routing-instance tables, PBR term action/counter, and overlay table scoping; no new issue.
- `pkg/dataplane/userspace/filtercounters.go` — filter/policer status indexes; checked nil status, composite keying, duplicate overwrite behavior, and read-only allocation; no new issue.
- `pkg/dataplane/userspace/filters.go` — firewall filter lowering; traced input/output v4/v6, protocol/ports, address and prefix-list positive/except semantics, fragments, ICMP, TCP flags, flexible match, DSCP, PBR, reject/discard, next-term, policers, strict/lenient markers, and empty sets; no new widening root.
- `pkg/dataplane/userspace/filters_address_except_3359_test.go` — mixed positive/except addresses; checked positive-wins tolerant fallback and clean complement behavior; no new issue.
- `pkg/dataplane/userspace/filters_address_matchany_except_4338_test.go` — universe-minus-prefix lowering; checked IPv4/IPv6 and specific-positive fallback; no new issue.
- `pkg/dataplane/userspace/filters_flex_match_3077_test.go` — flexible match; checked serialization, layer base, masking, default and rounded widths, and nil behavior; no new issue.
- `pkg/dataplane/userspace/filters_multivalue_2545_test.go` — multi-value protocol/DSCP/ICMP; checked all values survive and empty stays unconstrained; no new issue.
- `pkg/dataplane/userspace/filters_next_term_2544_test.go` — filter fall-through; checked explicit/implicit next term, PBR termination, and terminal actions; no new issue.
- `pkg/dataplane/userspace/filters_per_packet_match_2362_test.go` — TCP flags/fragments/ICMP; checked parsed masks, negation, malformed marker, fragment bit, and type/code vectors; no new issue.
- `pkg/dataplane/userspace/filters_port_except_2622_test.go` — port complements; checked source/destination wire fields and empty behavior; no new issue.
- `pkg/dataplane/userspace/filters_prefix_list_2506_test.go` — prefix-list resolution; checked `any`, literals, positive union, except, mixed fallback, undefined and empty lists; no new issue.
- `pkg/dataplane/userspace/filters_protocol_ipv6_3393_test.go` — IPv6 next-header protocol; checked emitted token and resolver parity; no new issue.
- `pkg/dataplane/userspace/filters_snapshot_integrity_3406_test.go` — tolerant-path integrity markers; checked bad ICMP/DSCP/TCP/flex values and mixed port warnings reject or narrow rather than widen; no new issue.
- `pkg/dataplane/userspace/filters_unresolved_except_5097_test.go` — unresolved complement references; checked sole-except match-all deny, match-any composition, and specific positive-wins behavior; no new issue.
- `pkg/dataplane/userspace/firewall_snapshot_render.go` — effective filter renderer; checked constrained-empty/except descriptions, protocol byte lists, actions/modifiers, and parity with enforced snapshot fields; no new issue.
- `pkg/dataplane/userspace/flow.go` — flow/session and AppID wire lowering; checked integer widths, session timeouts, ALG bits, MSS, flow-export reserved shape, catalog errors, IPv4/IPv6 sampling, and invalid collector handling; no new issue.
- `pkg/dataplane/userspace/flow_numwidth_agreement_test.go` — cross-language numeric widths; checked Go protocol structs against Rust schema expectations; no new issue.
- `pkg/dataplane/userspace/flow_wire_coerce_test.go` — malformed/out-of-range flow fields; checked safe sentinels/caps, collector continuation, full JSON shape, and GRE/power flags; no new issue.
- `pkg/dataplane/userspace/manager_cos_test.go` — CoS schema tests; checked three-color policers, exact/surplus/equal-flow, buffer percentages, classifier/rewrite fields, and undefined-reference handling; no gap promoted.
- `pkg/dataplane/userspace/manager_counters_test.go` — helper-to-BPF counter deltas; checked SYN-cookie, screen reasons, drops, NAT allocation/rule counters, reset/wrap behavior, and `safeDelta`; no new issue.
- `pkg/dataplane/userspace/manager_flow_test.go` — flow snapshot tests; checked timeout, nil TCP, ALG, collector/template, and absent config paths; no new issue.
- `pkg/dataplane/userspace/manager_nat_test.go` — source NAT pools and counter clear; checked pool fields, unsafe mode marking, helper IPC durability, and cached status clear; no new issue.
- `pkg/dataplane/userspace/manager_policycounters_test.go` — policy counters; checked helper index mapping, scheduled delete/re-add identity, committed identity, cached clear, and status IPC; no new issue.
- `pkg/dataplane/userspace/manager_routes_test.go` — route snapshots; checked destination-derived family and connected prefixes; no new issue.
- `pkg/dataplane/userspace/manager_screens_test.go` — screen snapshots; checked zone/profile linkage, missing refs, IPv4/IPv6-relevant fragment/ICMP/SYN fields, alarm-without-drop, SYN cookie, advanced fields, and ordering; no new issue.
- `pkg/dataplane/userspace/nat.go` — NAT address-name/port helpers; checked static/direct-feed union, unknown/empty fail-closed sentinels, destination/source symmetry, port bounds/coalescing, and reversed ranges; nested feed-backed address-set resolution is an indexed prior root and not re-reported.
- `pkg/dataplane/userspace/nat64.go` — NAT64 snapshot; checked source pools, IPv6 subscriber deterministic fields, /32-/64 bounds, fixed translated-port range, and fragment-header option; no new issue.
- `pkg/dataplane/userspace/nat64_deterministic_4559_test.go` — deterministic NAPT64; checked /32, /64, unsupported prefixes, missing config, block math, and IPv4 rejection; no new issue.
- `pkg/dataplane/userspace/nat64_frag_header_test.go` — NAT64 fragment policy; checked global option replication and default; no new issue.
- `pkg/dataplane/userspace/nat_address_name_failclosed_3425_test.go` — empty NAT address sets; checked SNAT/DNAT constraints remain never-match instead of match-any; no new issue.

### Host inbound, Junos host policy, interface/VLAN/RETH identity, and fabric

- `pkg/dataplane/userspace/fabric.go` — HA fabric snapshot/link state; checked dual-fabric ordering/dedup, parent/overlay ifindexes, peer MAC lookup, IPv4/IPv6 neighbors, and definite-down handling; no new issue.
- `pkg/dataplane/userspace/fabric_up_4082_test.go` — fabric `Up` wire behavior; checked resolved and unresolvable parent state; no new issue.
- `pkg/dataplane/userspace/host_inbound_classify.go` — simulator host-inbound classifier; traced no-stanza deny, full-admit, global ICMP/ND/ESP/AH accepts, per-interface views, ports, family, ICMP type, protocol tokens, and indeterminate queries against enforcement SSOT; no new allow/drop mismatch.
- `pkg/dataplane/userspace/host_inbound_classify_3627_test.go` — host-inbound simulator tests; checked admitting token, all, ident-reset deny, no stanza, and family gates; no new issue.
- `pkg/dataplane/userspace/host_inbound_owner_5489_test.go` — multiply-zoned interface ownership; checked deterministic owner, exact units, snapshot/view isolation, and physical branch guards; no new issue.
- `pkg/dataplane/userspace/host_inbound_per_iface_3362_test.go` — per-interface overrides; checked scoped views, zone union, wire fields, and configured marker; no new issue.
- `pkg/dataplane/userspace/host_inbound_phys_unit_3720_test.go` — physical/unit override inheritance; checked union and no cross-zone leak; no new issue.
- `pkg/dataplane/userspace/host_inbound_protocols_all_4411_test.go` — `protocols all`; checked it does not become full system-service admit; no new issue.
- `pkg/dataplane/userspace/host_inbound_unzoned_4420_test.go` — unzoned host addresses; checked they are represented for host protection rather than silently omitted; no new issue.
- `pkg/dataplane/userspace/host_inbound_view_grouping_3721_test.go` — effective-view grouping; checked order-insensitive token sets, distinct sets, per-interface enforcement union, and benchmark bounds; no new issue.
- `pkg/dataplane/userspace/interfaces.go` — interface snapshots; traced logical/physical names, VLAN parents, bondless RETH synthetic identity, zones, routing instances, filters, host-inbound overrides, addresses, MTU/MAC, queues, CoS, tunnels, and ingress bind targets; no new zone-confusion issue.
- `pkg/dataplane/userspace/interfaces_test.go` — kernel-name drift guard; checked snapshot/config naming parity for shared cases; no new issue.
- `pkg/dataplane/userspace/junos_host_deny.go` — Junos-host deny projection adapter; checked representability, lifeline exclusion, netdev scoping, v4/v6 rules, coarse exemptions, and empty-program handling; no new issue.
- `pkg/dataplane/userspace/junos_host_netdev_parity_test.go` — Junos-host interface scope parity; checked projection netdevs match snapshot identity; no new issue.
- `pkg/dataplane/userspace/junos_host_policy_3019_test.go` — Junos-host policy snapshot; checked rule action and host-zone identity; no new issue.
- `pkg/dataplane/userspace/junos_ping_icmp_3020_test.go` — Junos ping applications; checked v4/v6 echo-request constraints and all-ICMP unconstrained behavior; no new issue.
- `pkg/dataplane/userspace/manager_fabric_test.go` — fabric config mapping; checked local member and peer fields; no new issue.
- `pkg/dataplane/userspace/manager_interfaces_test.go` — interface/FIB identity tests; checked VLAN preference, bootstrap probes, local/NAT addresses, unit filters, tunnel flags, deterministic synthetic RETH IDs, fabric parents, ingress skip/dedup, and VLAN aliases; no gap promoted.

### Helper control, lifecycle, status, publication, maps, and adapters

- `pkg/dataplane/userspace/boot_probe.go` — boot/upgrade one-shot status probe; checked deadline, malformed/!OK/nil status, enabled+armed gating, socket override, and resource close; no new issue.
- `pkg/dataplane/userspace/boot_probe_test.go` — probe tests; checked live, each unarmed leg, !OK, missing/empty socket, and default/override path; no new issue.
- `pkg/dataplane/userspace/binding_ready_gate_test.go` — XSK binding readiness; checked registered/armed/ready/dead-worker conjunction and nil dead set; no new issue.
- `pkg/dataplane/userspace/clear_bounded_5304_test.go` — session clear memory/coverage; checked every v4/v6 key reaches helper with bounded chunks; no new issue.
- `pkg/dataplane/userspace/cold_path_sample_mask_test.go` — sample mask wire semantics; checked absent/default/zero/nonzero round trips; no new issue.
- `pkg/dataplane/userspace/cold_path_status_test.go` — cold-path telemetry status; checked sparse/default and Rust-emitted JSON widths; no new issue.
- `pkg/dataplane/userspace/configstore_helper_test.go` — shared test helper; checked active-config parsing failure behavior used by package tests; no production issue.
- `pkg/dataplane/userspace/control.go` — privileged queue/binding/forwarding parser; negative selector wrap was reproduced but is already indexed from codex-review-178/codex-review-175, so no duplicate finding.
- `pkg/dataplane/userspace/control_request_cap_2744_test.go` — control request cap; checked >16 MiB support, upper rejection, and Rust constant parity; no new issue.
- `pkg/dataplane/userspace/control_socket_deadline_4036_test.go` — control IPC deadlines; checked request-size scaling, large apply, and hung helper timeout; no new issue.
- `pkg/dataplane/userspace/control_test.go` — command parser tests; checked valid operations and usage errors; absence of negative selector cases belongs to the indexed prior root.
- `pkg/dataplane/userspace/controllers.go` — runtime link/HA/session adapters; checked nil failures, context cancellation, fabric0/fabric1 dispatch, post-map helper sync, and session-delta exposure; no new issue.
- `pkg/dataplane/userspace/legacy_dataplane.go` — compatibility adapter; checked nil safety and forwarding for config, overlays/feeds, scheduler, counters, HA, sessions, status, injection, link cycle, snapshot neighbors, event stream, readiness, and cursor iteration; no new issue.
- `pkg/dataplane/userspace/legacy_dataplane_batchclear_5096_test.go` — adapter batch/clear dispatch; checked authoritative helper deletes rather than BPF-only promotion; no new issue.
- `pkg/dataplane/userspace/legacy_dataplane_test.go` — adapter optional interfaces; checked delegation, nil receiver errors, and cursor unsupported sentinel; no new issue.
- `pkg/dataplane/userspace/link_cycle_test.go` — link-cycle publication; checked ctrl disable before stop, compat/strict status application, rebind, and adapter forwarding; no new issue.
- `pkg/dataplane/userspace/manager.go` — manager state/lifecycle surface; checked lock ownership, process/snapshot generations, capability status, deferred workers, route/feed overlays, event stream, mode, session source, and shutdown; no new issue independent of A6-b2-01.
- `pkg/dataplane/userspace/manager_compile.go` — compile/apply pipeline; traced strict/lenient errors, helper protocol gates, classifier map fail-closed update, deferred startup, full snapshot publication, HA clear/replay, scheduler republish, content/zone diagnostics, and post-success bookkeeping; route-overlay scheduler cache drift is a prior codex-review-178 root, not duplicated.
- `pkg/dataplane/userspace/manager_coupling_test.go` — runtime/legacy ownership boundaries; checked no embedded legacy manager and registry compatibility; no new issue.
- `pkg/dataplane/userspace/manager_generation.go` — generation management; checked mutex/atomic boundaries, FIB wrap behavior, map update ordering, and republish trigger; no new issue.
- `pkg/dataplane/userspace/manager_misc_test.go` — RST suppression and MAC formatting; checked retries, desired/applied changes, zero MAC, and formatting; no new issue.
- `pkg/dataplane/userspace/manager_neighbor.go` — neighbor publication/index; checked publishable filtering, forward-effective diff, post-success mutation, generation/hash bookkeeping, O(1) lookup, ifindex drift, and v4/v6 snapshots; no new issue.
- `pkg/dataplane/userspace/manager_overlay.go` — route-overlay partial publication; checked routes/PBR rebuild, protocol/disarm gates, dedup, FIB ordering, helper errors, and snapshot bookkeeping; scheduler-state advance on failed co-publication is already indexed from codex-review-178.
- `pkg/dataplane/userspace/manager_routes_test.go` — route snapshot tests are ledgered above under NAT/routing; reviewed once here by path and no new issue.
- `pkg/dataplane/userspace/manager_snapshot_test.go` — snapshot tests are ledgered above under policy/snapshot; reviewed once here by path and no new issue.
- `pkg/dataplane/userspace/manager_status.go` — live/cached status and privileged controls; checked stale fallback, capabilities arm gate, queue/binding requests, injection validation, delta drain/export, and map application errors; no new issue beyond prior negative-ID root.
- `pkg/dataplane/userspace/manager_testhelpers_test.go` — package test control server/helper utilities; checked framing and cleanup assumptions; no production issue.
- `pkg/dataplane/userspace/manager_worker_arm_5134.go` — deferred-MAC arm debt; checked generation commit-after-success, protocol/capability gates, retained debt on failure, superseding apply, workerless snapshot, and status bookkeeping; no new issue.
- `pkg/dataplane/userspace/manager_worker_arm_5134_test.go` — arm-debt tests; checked helper-down retention, already-armed settle, recovery publish, and generation monotonicity; no gap promoted.
- `pkg/dataplane/userspace/maps.go` — BPF map-name registry; checked scope and compatibility aliases; no new issue.
- `pkg/dataplane/userspace/maps_decouple_test.go` — map-name AST/parity canaries; checked literal/alias/concat bypass detection, loader parity, malformed declarations, and cross-file concatenation; no new issue.
- `pkg/dataplane/userspace/maps_sync.go` — shim-map publication; traced ctrl fail-closed behavior, binding READY/dead-worker gates, VLAN aliases, ingress/local/interface-NAT addresses, add-before-prune, enumeration completeness, map caps, heartbeat slots, XSK liveness, modes, counters, and cache invalidation; no new forwarding widen.
- `pkg/dataplane/userspace/maps_sync_addrlist_prune_3924_test.go` — local-address map reconciliation; checked transient enumeration failure retains stale rows and complete enumeration prunes; no new issue.
- `pkg/dataplane/userspace/maps_sync_cap_test.go` — map cap/fail-closed tests; checked over-cap ifindex, live ctrl disable, blind failure, add-before-remove, NAT replacement, watchdog guard, and Rust cap parity; no new issue.
- `pkg/dataplane/userspace/maps_sync_heartbeat_slots_4572_test.go` — heartbeat slot bounds; checked low/high worker values and map capacity; no new issue.

### HA, session synchronization, event stream, injection, mirrors, and telemetry

- `pkg/dataplane/userspace/eventstream.go` — event listener, framing, callbacks, replay/ACK, session/dataplane decoders, drain, counters, and concurrency; checked gaps, malformed/unknown frames, queue bounds, reconnect watermarks, callback locks, frame writes, v4/v6/NAT/zone metadata, and resource lifecycle; A6-b2-01 is the listener-start failure path. FullResync queue ordering is a prior codex-review-178 root.
- `pkg/dataplane/userspace/eventstream_test.go` — event-stream tests; checked decoding widths, NAT64, high zone/ifindex/RG IDs, callback-before/after readiness, malformed/unknown ACKs, reconnect, pause/resume, gap classes, drain fences, raw/decoded events, logging fanout, and counters; no listener-start failure assertion, supporting A6-b2-01.
- `pkg/dataplane/userspace/eventstream_writeframe_race_4835_test.go` — write serialization; checked deadline/write atomicity across concurrent writers; no new issue.
- `pkg/dataplane/userspace/fairness.go` — CoS RSS summaries/expectations; checked sparse/overflow workers, bounded slots, interface re-enumeration, weighted CoV, missing queues, and allocations off hot path; no new issue.
- `pkg/dataplane/userspace/fairness_test.go` — RSS fairness tests; checked bounds, fallback workers, missing queues, name-key stability, and unresolved interfaces; no new issue.
- `pkg/dataplane/userspace/fairness_throughput.go` — rolling throughput window; checked counter resets, pruning, idle progress, queue/worker bounds, starved-flow dedup, saturation, equal-flow estimates, and map growth bounded by configured queues; no new issue.
- `pkg/dataplane/userspace/fairness_throughput_test.go` — throughput tests; checked rolling CoV, starvation, idle/boundary samples, resets, pruning, equal-flow validity, and worker caps; no new issue.
- `pkg/dataplane/userspace/inject.go` — diagnostic packet command and helper request; checked tuple protocol gate, v4/v6 ICMP restriction, family/address/port parsing, packet-length cap, generation metadata, and encode/decode; negative slot wrap is the same indexed codex-review-175 root.
- `pkg/dataplane/userspace/inject_test.go` — injection tests; checked emit tuple, old helper rejection, source requirement, unsupported protocol, metadata transport, maximum/malformed length, and pre-IPC validation; no new issue.
- `pkg/dataplane/userspace/manager_ha.go` — HA state/session mirror; traced RG active/watchdog ordering, arm/disarm, takeover readiness, fabric state, counters, v4/v6/NAT64 session sync, generation/policy/app metadata, tunnel/VLAN/RETH egress identity, bounded deletes, lock release, and zone IDs; no new stale-permit or HA fail-open root.
- `pkg/dataplane/userspace/manager_ha_test.go` — HA tests; checked readiness reasons, persistent-NAT boundary, standby/active liveness, one-time cleanup, RG activation, map merge/clear/seed, signatures, arm policy, transition guard, busy binding recovery, stop reset, and watchdog throttle; no gap promoted.
- `pkg/dataplane/userspace/manager_sessionsync_snapshot_5007_test.go` — session pair snapshot coherence; checked forward/reverse resolution under one snapshot lock; no new issue.
- `pkg/dataplane/userspace/manager_sessionsync_test.go` — session wire tests; checked v4/v6 byte order, owner/egress/tx/VLAN/tunnel identity, both NAT legs, NAT64 v4 pool, log flags, policy counters, inactivity, generations, reverse suppression, mirror health, and socket path; no new issue.
- `pkg/dataplane/userspace/manager_tunnels_test.go` — tunnel snapshots; checked unit identity, routing table, RG source ownership, GRE/WireGuard fields, required endpoints, and private-key control-channel contract; no new issue.
- `pkg/dataplane/userspace/mirrors.go` — port-mirror lowering; checked one-output-per-ingress, deterministic conflict owner, negative sampling, unresolved interfaces, and scoped degradation; no new issue.
- `pkg/dataplane/userspace/manager_mirrors_test.go` — mirror tests; checked real interface resolution, duplicate ingress, missing output, and negative rate; no new issue.


## A6-b3


### NAT lowering and counters

- `pkg/dataplane/userspace/nat_destination.go` — DNAT address/name, application, protocol/port, pool, and scope lowering inspected; invalid constraints retain never-match behavior and no new widening found.
- `pkg/dataplane/userspace/nat_nptv6.go` — NPTv6/static-NAT exclusion and family handling inspected; no ordering or representability defect found.
- `pkg/dataplane/userspace/nat_source.go` — SNAT scope tiering, address-name/feed expansion, application terms, deterministic and persistent modes inspected; stable scope order and invalid-term sentinels are coherent.
- `pkg/dataplane/userspace/nat_static.go` — static mapping, port clamping, source scope, and counters inspected; malformed mapped ports do not broaden matching.
- `pkg/dataplane/userspace/natcounters.go` — helper compatibility and clear serialization inspected; lock and error behavior are consistent with peer counter clear paths.
- `pkg/dataplane/userspace/nat_dest_address_name_3229_test.go` — positive/union/undefined destination-name and SNAT resolution coverage inspected; substantive fail-closed assertions present.
- `pkg/dataplane/userspace/nat_dest_prefix_3164_test.go` — CIDR/host destination classification coverage inspected; no family-collapse gap found.
- `pkg/dataplane/userspace/nat_dnat_app_dport_3857_test.go` — app plus explicit destination-port precedence and malformed-port coverage inspected; valid override and never-match cases covered.
- `pkg/dataplane/userspace/nat_dnat_app_empty_3434_test.go` — undefined/empty app versus absent-app wildcard coverage inspected; fail-closed distinction is pinned.
- `pkg/dataplane/userspace/nat_dnat_app_match_3437_test.go` — source-port and ICMP type/code app constraints inspected; all-invalid sentinel and unconstrained app guards present.
- `pkg/dataplane/userspace/nat_dnat_match_dport_3446_test.go` — zero, overflow, nonnumeric, partial-valid, absent, and valid ports inspected; no widening regression found.
- `pkg/dataplane/userspace/nat_dnat_off_3844_test.go` — scoped DNAT exemption emission inspected; off rule remains an explicit ordered row.
- `pkg/dataplane/userspace/nat_dnat_pool_3450_test.go` — malformed pool port/address fail-closed cases inspected; no host-prefix coercion found.
- `pkg/dataplane/userspace/nat_dnat_port_range_3449_test.go` — bounded range representation inspected; wide ranges are not expanded into resource-heavy lists.
- `pkg/dataplane/userspace/nat_feed_overlay_3303_test.go` — source/destination feed overlay on SNAT/DNAT inspected; static plus feed union coverage is substantive.
- `pkg/dataplane/userspace/nat_l4_match_3429_test.go` — lenient malformed L4, app resolution, source ports, and unconstrained semantics inspected; never-match behavior covered.
- `pkg/dataplane/userspace/nat_match_multivalue_3431_test.go` — repeated protocol/application union inspected; first-value collapse regressions are pinned.
- `pkg/dataplane/userspace/nat_per_uplink_test.go` — per-uplink zones, counters, source/destination multiplicity, and non-TCP/UDP inspected; no new cross-uplink leakage found.
- `pkg/dataplane/userspace/nat_reversed_port_range_3726_test.go` — reversed/equal application ranges on SNAT and DNAT inspected; reversed ranges fail closed.
- `pkg/dataplane/userspace/nat_scope_3096_test.go` — SNAT/static/DNAT scope carriage inspected; required context fields are asserted.
- `pkg/dataplane/userspace/nat_scope_precedence_4161_test.go` — interface/zone/RI tier order, stable same-tier order, contiguity, and mixed-side specificity inspected; no ordering inversion found.
- `pkg/dataplane/userspace/nat_source_address_name_2416_test.go` — source-name resolution, union, undefined fail-close, and SNAT parity inspected.
- `pkg/dataplane/userspace/nat_source_deterministic_4559_test.go` — IPv4 deterministic fields, IPv6 deferred mode, and absence inspected; unsupported IPv6 behavior is explicit rather than silently deterministic.
- `pkg/dataplane/userspace/nat_source_pool_port_3906_test.go` — translated, no-translation, and default ranges inspected; no port-zero wildcard confusion found.
- `pkg/dataplane/userspace/nat_source_pool_port_5457_test.go` — reversed/invalid pool range unusable marker inspected; publication does not leave the rule usable.
- `pkg/dataplane/userspace/static_nat_mapped_port_2491_test.go` — mapped-port wire and malformed clamp coverage inspected; no unexpected wrap found.
- `pkg/dataplane/userspace/static_nat_source_address_3435_test.go` — plural/singular/absent static source scope inspected; no accidental match-any from a configured list found.

### Policy lowering, identity, and representability

- `pkg/dataplane/userspace/policies.go` — zone-pair/global slot walking, expansion spans, sentinels, and runtime ID bounds inspected; no ID spill found.
- `pkg/dataplane/userspace/policies_addrbook.go` — content IDs, collision probes, feed/set recursion, canonicalization, and dedup inspected; bounded probes fail build rather than aliasing content.
- `pkg/dataplane/userspace/policies_ids.go` — stable/runtime ID projection and expansion accounting inspected; read/write namespace stays shared.
- `pkg/dataplane/userspace/policies_lower.go` — all policy fields and global scope compatibility lowering inspected; **A6B3-01**.
- `pkg/dataplane/userspace/policies_reject.go` — content rejection attribution and scope rendering inspected; side-specific diagnostics preserve offending tokens.
- `pkg/dataplane/userspace/policies_representable.go` — literal/feed/book/set/cycle representability inspected; structural failure and concrete contribution are separated correctly.
- `pkg/dataplane/userspace/policies_scheduler.go` — absent/present scheduler-state behavior inspected; unknown state does not spuriously activate a known inactive rule.
- `pkg/dataplane/userspace/policycounters.go` — bulk/per-rule index mapping, unpublished state, helper clear, and lock release inspected; no namespace or lock inversion found.
- `pkg/dataplane/userspace/nested_app_set_policy_test.go` — nested application-set expansion inspected; resolved leaf match is asserted.
- `pkg/dataplane/userspace/policy_global_zone_3148_test.go` — global structural tier plus scoped context inspected; single-zone case is covered but does not refute **A6B3-01**.
- `pkg/dataplane/userspace/policy_match_excluded_test.go` — source/destination inversion flags inspected; both wire bits are pinned.
- `pkg/dataplane/userspace/policy_namespace_3143_3145_test.go` — nil sets, span accumulation, exact fill, spill rejection, counters, and cross-set collision inspected; boundary coverage is strong.
- `pkg/dataplane/userspace/policy_reject_reasons_3376_test.go` — zone-pair/global rejection labels and side attribution inspected; diagnostics are unambiguous.
- `pkg/dataplane/userspace/policy_runtime_ids_3063_test.go` — runtime IDs against built snapshots inspected; producer/consumer agreement is asserted.
- `pkg/dataplane/userspace/policycounters_bulk_test.go` — bulk parity, one-time index construction, and unlocked resolution inspected; no hot lock retention found.
- `pkg/dataplane/userspace/scoped_global_zoneset_4626_test.go` — plural full set and singular first-element projection inspected; its “safe degradation” assertion exposes **A6B3-01**.

### Zones and host inbound

- `pkg/dataplane/userspace/zones.go` — lifeline classification, host address parsing, and authoritative interface-zone map inspected; deterministic ownership is used consistently.
- `pkg/dataplane/userspace/zones_host_inbound.go` — zoned/unzoned address collection, VRRP/kernel-learned addresses, services/protocols, and lifelines inspected; no unscoped host exposure found.
- `pkg/dataplane/userspace/zones_observability.go` — addressless enforcing zones/interfaces and ambiguous local addresses inspected; observability follows enforcement identity.
- `pkg/dataplane/userspace/zones_override.go` — physical/unit additive overrides and cross-zone ownership guards inspected; no override token bleed found.
- `pkg/dataplane/userspace/zones_quarantine.go` — stable-ID collision scrub across zones/interfaces/policies inspected; **A6B3-02**.
- `pkg/dataplane/userspace/zones_snapshot.go` — stable IDs, default host-inbound deny, per-interface override separation, and TCP RST inspected; nil zone remains enforcing.
- `pkg/dataplane/userspace/zonecounters.go` — zone clear and old-helper behavior inspected; errors are propagated under the manager lock.
- `pkg/dataplane/userspace/zone_counters_status_test.go` — counter status and clear path inspected; zone labels and helper interaction are asserted.
- `pkg/dataplane/userspace/zone_local_addressbook_3061_test.go` — zone-local book selection inspected; no cross-zone address-book resolution found.
- `pkg/dataplane/userspace/zones_addressless_3698_test.go` — addressless enforcing zone visibility inspected; deny posture remains observable.
- `pkg/dataplane/userspace/zones_addressless_iface_3710_test.go` — per-interface addressless visibility inspected; logical identity is covered.
- `pkg/dataplane/userspace/zones_ambiguous_3718_test.go` — duplicate host-address ambiguity reporting inspected; deterministic output is asserted.
- `pkg/dataplane/userspace/zones_collision_3719_test.go` — collision quarantine and single-zone scoped-global drop inspected; missing partial multi-zone preservation leads to **A6B3-02**.
- `pkg/dataplane/userspace/zones_host_inbound_test.go` — default deny, configured tokens, views, VRRP, learned addresses, overrides, and lifelines inspected; broad host-inbound coverage is present.
- `pkg/dataplane/userspace/zones_stable_id_3704_test.go` — snapshot/display/HA ownership namespace inspected; stable name-derived identity is pinned.
- `pkg/dataplane/userspace/zones_tcp_rst_3071_test.go` — per-zone TCP reset bit inspected; no action inversion found.

### Snapshot process, protocol, routing, HA, and ancillary dataplane state

- `pkg/dataplane/userspace/neighbors.go` — forwarding equality, publishability, monitored ifindexes, state strings, and ownership inspected; malformed rows are filtered consistently with hashing.
- `pkg/dataplane/userspace/process.go` — helper start/stop, binary selection, config equality, and FIB sync inspected; resource teardown is ordered and no new leak found.
- `pkg/dataplane/userspace/process_control.go` — request cap, deadlines, framing, status decode, and session socket inspected; bounded control payload and error propagation are present.
- `pkg/dataplane/userspace/process_linkcycle.go` — strict/compat control disable, helper stop, rebind delay, and notify inspected; transit remains dropped on degraded strict path.
- `pkg/dataplane/userspace/process_napi.go` — async queue bootstrap and ICMP/UDP neighbor probes inspected; goroutine inputs are copied and work is off hot path.
- `pkg/dataplane/userspace/process_status.go` — deferred publish, same-plan exception, protocol gate, pre-publish disarm, hash bookkeeping, HA poll, and arm retry inspected; publication errors retain prior applied state.
- `pkg/dataplane/userspace/protocol.go` — complete Go JSON wire DTOs, defaults, numeric widths, status aliases, and policy/zone/NAT fields inspected; no null or integer-width regression found, but v2 lacks a feature gate relevant to **A6B3-01**.
- `pkg/dataplane/userspace/routes.go` — route/table/family normalization, ip-rule errors, PBR exclusion, rib-group leaks, overlay replacement, dedup, and deterministic total order inspected; no selector widening found.
- `pkg/dataplane/userspace/runtime_delta.go` — generation, family, reason, status, and HA delta adaptation inspected; no stale-generation conversion found.
- `pkg/dataplane/userspace/screens.go` — profile lowering, missing refs, SYN-cookie material, and support gates inspected; absent profiles remain explicit.
- `pkg/dataplane/userspace/tunnels.go` — endpoint identity, eligibility, WireGuard peers, sort/dedup, and transition logging inspected; no ID-shift or stale endpoint found.
- `pkg/dataplane/userspace/wire_uint8list.go` — numeric array marshal/unmarshal, null handling, range/type errors inspected; byte lists cannot silently decode strings or overflow.
- `pkg/dataplane/userspace/protocol_failopen_2124_test.go` — protocol/port representability, sentinels, and disarm ordering inspected; old-helper policy-content disarm does not cover the semantically valid multi-zone shape in **A6B3-01**.
- `pkg/dataplane/userspace/protocol_null_collections_2214_test.go` — empty NAT/filter collections inspected; whole-snapshot Rust decode regression is pinned.
- `pkg/dataplane/userspace/protocol_test.go` — broad JSON round-trip/backward-default inventory inspected; additive fields default cleanly, but no helper-feature negotiation test covers **A6B3-01**.
- `pkg/dataplane/userspace/route_overlay_test.go` — whole-entry replacement, hash delta, helperless cache, failed publication retention, and retry inspected; fail-closed publication bookkeeping is substantive.
- `pkg/dataplane/userspace/routes_dedupe_3770_test.go` — distinct same-prefix routes and deterministic order inspected; discard/connected entries are retained.
- `pkg/dataplane/userspace/routes_family_normalize_4423_test.go` — VRF-preserving v4/v6 table normalization inspected; no family alias found.
- `pkg/dataplane/userspace/routes_fib_metadata_test.go` — preference, ECMP, and interface RI metadata inspected; all next hops survive lowering.
- `pkg/dataplane/userspace/routes_ipv6_nexttable_3768_test.go` — per-family next-table leak inspected; IPv6 table names remain family-correct.
- `pkg/dataplane/userspace/routes_pbr_priority_4479_test.go` — PBR-band exclusion versus route-leak inclusion inspected; constrained PBR is not widened.
- `pkg/dataplane/userspace/routes_ribgroup_leak_3876_test.go` — per-prefix capture and destinationless skip inspected; unrepresentable whole-table leaks are not fabricated.
- `pkg/dataplane/userspace/routes_rulelist_3772_test.go` — netlink error propagation and malformed overlay prefix skip inspected; partial route publication is rejected.
- `pkg/dataplane/userspace/runtime_delta_test.go` — DTO adaptation and HA controller update/sync ordering inspected; failed forwarding update does not publish fabric state.
- `pkg/dataplane/userspace/screens.go` — screen ordering was cross-checked with snapshot assembly; no per-packet allocation is introduced by this control-plane builder.
- `pkg/dataplane/userspace/shim_loader_boundary_test.go` — startup shim boundary and legacy object references inspected; retired loader fallback is absent.
- `pkg/dataplane/userspace/snapshot_allowlist_test.go` — management/tunnel filtering, VLAN parent binding, and bind-target SSOT inspected; no unintended AF_XDP ownership found.
- `pkg/dataplane/userspace/snapshot_neighbors_1197_test.go` — publishability and forwarding equality inspected; non-forwarding churn does not alter the publish set.
- `pkg/dataplane/userspace/three_color_default_4535_test.go` — unspecified versus color-aware forwarding support inspected; unsupported mode disarms while default does not false-deny.
- `pkg/dataplane/userspace/tunnels_test.go` — removal, TTL, multi-unit identity, eligibility flap, collision, naming, and peer ordering inspected; deterministic behavior is covered.
- `pkg/dataplane/userspace/userspace_boot_canary_test.go` — adapter and registry boot shape inspected; userspace remains the selected implementation.
- `pkg/dataplane/userspace/wg_status_test.go` — populated/absent WireGuard status decode inspected; omitted legacy state defaults safely.
- `pkg/dataplane/userspace/wire_uint8list_test.go` — arrays, decode rejection, DSCP wire structs, raw-slice ban, and full snapshot decode inspected; byte serialization compatibility is pinned.
- `pkg/dataplane/userspace/xdp_shim_decouple_test.go` — ctrl-disabled/binding-not-ready/XSK failure strict drops and local-control passes inspected; no legacy fail-open fallback found.

### Formatting and operator parity

- `pkg/dataplane/userspace/format/buffers.go` — utilization/counter rendering and structured parity inspected; output-only arithmetic cannot alter forwarding.
- `pkg/dataplane/userspace/format/buffers_model.go` — aggregation, capacity fallbacks, saturation, CoS rows, and scopes inspected; no divide-by-zero or wrap found.
- `pkg/dataplane/userspace/format/cos.go` — interface/queue views, rates, bursts, and optional IDs inspected; bounded display conversion is coherent.
- `pkg/dataplane/userspace/format/cos_sections.go` — queue/detail/histogram/runtime index and old JSON fallback inspected; no unbounded dataplane hot-path work applies.
- `pkg/dataplane/userspace/format/cos_show.go` — selectors, classifiers, scheduler maps, classes, and codepoints inspected; show selection does not misstate configured names.
- `pkg/dataplane/userspace/format/math.go` — saturating add/sub inspected; overflow/underflow clamps are correct.
- `pkg/dataplane/userspace/format/status.go` — HA role, worker-map limit parsing, binding tuple formatting, protocol names, and NAT permit display inspected; invalid limits return errors.
- `pkg/dataplane/userspace/format/status_sections.go` — security/NAT/CoS/TX/slow-path/worker aggregates inspected; counters saturate and remain presentation-only.
- `pkg/dataplane/userspace/format/wireguard.go` — peer/tunnel detail, key rendering, reason rows, and handshake age inspected; malformed keys are not presented as valid keys.
- `pkg/dataplane/userspace/format/buffers_golden_test.go` — buffer golden parity inspected; structured/detail changes are pinned.
- `pkg/dataplane/userspace/format/buffers_test.go` — aggregation, fallback, utilization, saturation, and detail coverage inspected; no arithmetic defect found.
- `pkg/dataplane/userspace/format/cos_golden_test.go` — CoS golden output inspected; stable presentation contract present.
- `pkg/dataplane/userspace/format/cos_show_test.go` — queue/classifier/map/class selector coverage inspected; no false inventory result found.
- `pkg/dataplane/userspace/format/cos_test.go` — runtime/config merge, old JSON, queue telemetry, rates, histograms, and admission counters inspected; compatibility display is broadly covered.
- `pkg/dataplane/userspace/format/status_golden_test.go` — status golden output inspected; section and counter labels are pinned.
- `pkg/dataplane/userspace/format/status_test.go` — summary, HA, worker maps, bindings, tuple formatting, limits, and counter aggregates inspected; malformed selector handling is covered.
- `pkg/dataplane/userspace/format/wireguard_test.go` — WireGuard summary/detail/key/age/reason rendering inspected; absent and malformed values are covered.


## A7-b1


Each entry records subsystem, reviewed dimensions, and either finding IDs or a substantive negative result.

- `pkg/daemon/aggregator_callback_4964_test.go` | system logging | callback ownership, disable/re-enable, concurrency | Negative: pins one callback and atomic live-pointer replacement; no leak or stale authorization side effect.
- `pkg/daemon/aggregator_flush_5313_test.go` | system logging | config swap, buffered resource lifetime | Negative: old aggregation windows flush before replacement and shutdown paths are bounded.
- `pkg/daemon/api_bind_clamp_5127_test.go` | management API | auth fail-closed, IPv4/IPv6 bind exposure | Negative: unauthenticated HTTP/HTTPS binds clamp to loopback; authenticated configuration remains explicit.
- `pkg/daemon/apply_ctx_cancel_test.go` | apply runtime | cancellation boundaries, publication atomicity | Negative: daemon-stop cancellation is separated from request cancellation and tested at coarse boundaries.
- `pkg/daemon/apply_interface_reconcile_failclosed_5310_test.go` | runtime apply | xfrmi/bond/tunnel failures, false success | Negative: interface reconcile errors reach the tail join; no silent successful commit.
- `pkg/daemon/apply_serialize_test.go` | runtime apply | apply semaphore, commit/apply serialization | Negative: concurrent apply and commit pairs cannot interleave.
- `pkg/daemon/archive_atomic_4621_test.go` | archival | atomic file publication, lifetime | Negative: staged archive publication is atomic.
- `pkg/daemon/archive_config_3867_test.go` | archival | active-config source, temporary cleanup | Negative: archives use active state and clean staging files.
- `pkg/daemon/archive_timer_4078_test.go` | archival | timer replacement, shutdown | Negative: interval/site changes reschedule and disabled config stops the worker.
- `pkg/daemon/bootstrap.go` | boot/runtime | strict/lenient load, fail-closed FRR, lifeline, resource lifetime | Negative: compile-failed state protects management and clears stale routing when forwarding is not armed; no Z4/Z5 root.
- `pkg/daemon/bootstrap_lifeline_nonpci_4815_test.go` | boot | non-PCI lifeline identity | Negative: malformed/unsupported identity fails toward no takeover.
- `pkg/daemon/bootstrap_rollback_test.go` | boot/apply | first-commit rollback | Negative: first takeover rollback returns to bootstrap; later rollback does not over-teardown.
- `pkg/daemon/bootstrap_test.go` | boot | error classification, boot matrix, protected interfaces | Negative: unreadable/compile-failed/never-committed cases are distinguished and management remains protected.
- `pkg/daemon/coalescence.go` | host tuning | parsing, allowlist, bounds, idempotence | Negative: only allowed mlx devices are touched and invalid ethtool output is skipped.
- `pkg/daemon/coalescence_test.go` | host tuning tests | adaptive modes, defaults, mixed devices | Negative: positive/negative parser and write-gating coverage present.
- `pkg/daemon/commit_confirm_demote_4378_test.go` | HA config | demotion/rollback lifecycle | Negative: RG0 demotion confirms pending commit-confirmed state before read-only transition.
- `pkg/daemon/compile_error_policy_test.go` | apply policy | required protocol gates | Negative: required helper protocol incompatibilities abort the apply.
- `pkg/daemon/compile_health_test.go` | health | repeated failure state | Negative: compile failures and recovery are surfaced.
- `pkg/daemon/config_arrival_naming_4179_test.go` | interface identity | HA first config, retry | Negative: cluster naming is one-shot only after success and empty config does not consume the retry.
- `pkg/daemon/config_sync_test.go` | HA config | authority, replay, freshness | Negative except F-01: primary rejection and peer-connect push gates are tested, but tail-error invalidation is not.
- `pkg/daemon/configstore_helper_test.go` | config store | fixture contract | Negative: helper only constructs isolated durable stores.
- `pkg/daemon/configsync_tail_error_test.go` | HA/apply | nonfatal tail error propagation | F-01: tests cover primary continuing to send config, not standby invalidation after its tail failure.
- `pkg/daemon/daemon.go` | daemon state | locks, atomics, ownership | Negative: reviewed apply/HA/scheduler/host-inbound state ownership; no unguarded mutation found in lane state.
- `pkg/daemon/daemon_apply.go` | runtime ordering | snapshot publication, nft tail, policy invalidation, HA sync | F-01: standby sync returns before invalidation on a nonfatal tail error; primary path correctly continues.
- `pkg/daemon/daemon_apply_runtime_test.go` | apply tests | nft failure and downstream consumers | Negative except F-01: local tail errors are surfaced and downstream ApplyResult wiring is pinned; no synced-standby counterpart.
- `pkg/daemon/daemon_archive_timer.go` | archival | timer keying, cancellation | Negative: replacement cancels old timer and immutable site copies are used.
- `pkg/daemon/daemon_cluster_bind.go` | HA transport | literal parsing, loopback/auth clamp, family | Negative: unauthenticated binds and peer-family selection fail toward loopback/fallback.
- `pkg/daemon/daemon_ddns.go` | DDNS/HA | per-RG writer gate, overlap, locking | Negative: only an owning RG writes, overlap attribution is deterministic, and reconcile is serialized.
- `pkg/daemon/daemon_ddns_scope_test.go` | DDNS tests | scope/RG attribution | Negative: overlapping pools and partial ownership are covered.
- `pkg/daemon/daemon_ddns_surface_a.go` | DDNS surface A | observer lifetime, public-address gate, HA ownership | Negative: transient absence does not withdraw and RG0 single-writer gate is explicit.
- `pkg/daemon/daemon_ddns_surface_a_test.go` | DDNS tests | static/DHCP/check-IP, cancellation, determinism | Negative: observer source and no-fallback behavior have broad positive/negative coverage.
- `pkg/daemon/daemon_ddns_test.go` | DDNS tests | standalone/HA gates, nudge coalescing | Negative: backup cannot publish and early nudges do not delete.
- `pkg/daemon/daemon_dhcp.go` | DHCP | RETH identity, lease-driven recompile, relay ownership | Negative: Junos-to-Linux identity and RG relay gate are explicit; no policy ordering defect.
- `pkg/daemon/daemon_dhcp_filter_4647_test.go` | DHCP/HA | tagged/untagged RETH filtering | Negative: master-only server config handles unit identity.
- `pkg/daemon/daemon_dhcp_lease_sync.go` | DHCP/HA | peer seed/push, fingerprint, goroutine lifetime | Negative: knob, connection, and master gates prevent dual-writer behavior.
- `pkg/daemon/daemon_dhcp_lease_sync_test.go` | DHCP/HA tests | gate, seed, fingerprint | Negative: backup suppression and peer seed are covered.
- `pkg/daemon/daemon_dhcp_leasesync_4647_test.go` | DHCP/HA tests | day-2 loop lifecycle | Negative: on/off and comms-down launch behavior are covered.
- `pkg/daemon/daemon_dhcp_relay_gate_test.go` | DHCP relay | per-RG failover gate | Negative: failover re-evaluates ownership and non-RG interfaces remain available.
- `pkg/daemon/daemon_dhcprelay_reconcile_test.go` | DHCP relay | add/remove runtime reconcile | Negative: nil manager, first enable, and removal are covered.
- `pkg/daemon/daemon_dns.go` | DNS | symlink replacement, atomic write, merge ordering | Negative: stale resolved artifacts are removed and boot-empty behavior avoids destructive blanking.
- `pkg/daemon/daemon_dns_test.go` | DNS tests | idempotence, precedence, deterministic leases | Negative: dangling symlink and boot/runtime empty cases are covered.
- `pkg/daemon/daemon_eventoptions_reconcile_test.go` | event options | day-2 lifecycle, callback order | Negative: manager exists before RPM callback use and nil config is safe.
- `pkg/daemon/daemon_fabric_monitor_4031_test.go` | HA fabric | netlink resubscribe, cancellation | Negative: closed channels resubscribe and context cancellation exits.
- `pkg/daemon/daemon_feeds.go` | dynamic policy feeds | hash, snapshot publication, lifetime | Negative: producer generation is reconciled before snapshot handoff; no stale binding found.
- `pkg/daemon/daemon_feeds_reconcile_5036_test.go` | feeds tests | day-2 add/remove/hash | Negative: config changes reconcile and nil manager is safe.
- `pkg/daemon/daemon_flow.go` | flow/runtime | route overlays, export shutdown, parsing, link monitor | Negative: overlay publication is ordered before FIB generation and link subscriptions self-heal.
- `pkg/daemon/daemon_flowexport.go` | observability | callback ownership, queue bounds, config swap | Negative: atomic bundles and admission leases avoid stale callback use; queues expose drops.
- `pkg/daemon/daemon_flowexport_flowdir_test.go` | flow export tests | direction parity | Negative: egress direction metadata is covered.
- `pkg/daemon/daemon_flowexport_reconcile_test.go` | flow export tests | add/remove/swap/failure | Negative: failed replacement keeps old exporter and callback count is stable.
- `pkg/daemon/daemon_flowexport_session_close_test.go` | flow export tests | frame parsing, family isolation | Negative: only SESSION_CLOSE drives correct family instances.
- `pkg/daemon/daemon_flowtrace_3932_test.go` | flow trace | callback lifetime | Negative: reconcile maintains exactly one callback.
- `pkg/daemon/daemon_forwarding_status.go` | status | helper compatibility, cached polling | Negative: runtime adapters are type-probed and status sampling does not double-poll.
- `pkg/daemon/daemon_forwarding_status_test.go` | status tests | dataplane swap, userspace adapter | Negative: current runtime object is used after swap.
- `pkg/daemon/daemon_gc.go` | sessions | runtime-domain adapter | Negative: GC receives the current SessionStore/Telemetry domains; policy invalidation remains separate.
- `pkg/daemon/daemon_gc_test.go` | sessions tests | legacy/runtime domain compatibility | Negative: adapter preserves both runtime domains.
- `pkg/daemon/daemon_goroutine_shutdown_5308_test.go` | lifecycle | scheduler/RPM join | Negative: stop cancels and joins without late syscalls.
- `pkg/daemon/daemon_ha.go` | HA lifecycle | activation/demotion order, first packet, neighbors, services | Negative: activation sets `rg_active` before ownership and demotion prepares/blackholes before clear; no new first-packet defect.
- `pkg/daemon/daemon_ha_fabric.go` | HA fabric | dual links, cached entry retention, resubscribe | Negative: both fabric slots refresh independently and cached forwarding is retained on transient miss.
- `pkg/daemon/daemon_ha_fabric_test.go` | HA fabric tests | cache retention, wake coalescing | Negative: primary/secondary cache and dual wake paths are covered.
- `pkg/daemon/daemon_ha_fence_3917_test.go` | HA safety | dynamic RG set, startup fencing | Negative: fencing reads current config and is nil/config-only safe.
- `pkg/daemon/daemon_ha_sync.go` | HA config/session | bulk readiness, config authority, callback retry | F-01: callback treats promoted config plus tail failure as failed, while the next equal-text delivery skips the missing invalidation.
- `pkg/daemon/daemon_ha_sync_test.go` | HA sync tests | clock discontinuity suppression | Negative: backward/forward clock behavior does not leave failover suppression stuck.
- `pkg/daemon/daemon_ha_userspace.go` | userspace HA | controller adaptation | Negative: narrow adapter delegates readiness/demotion without alternate policy state.
- `pkg/daemon/daemon_ha_userspace_convert.go` | session HA wire | tuple/NAT/policy metadata, IPv4/IPv6 | Negative: policy ID/log/counter/timeout and NAT64 metadata are carried through conversion.
- `pkg/daemon/daemon_ha_userspace_export.go` | session HA export | owner-RG selection | Negative: exports enumerate configured RGs and include RG0.
- `pkg/daemon/daemon_ha_userspace_readiness.go` | session HA | peer barrier, demotion, retry | Negative: planned demotion requires connected/quiescent peer and failed prep restarts prime retry.
- `pkg/daemon/daemon_ha_userspace_stream.go` | session HA | delta ownership, full resync, fallback polling | Negative: owner-RG gate and connected-primary checks prevent standby publication; full resync is bounded by runtime export.
- `pkg/daemon/daemon_ha_vip.go` | HA VIP | direct ownership, stable LL, GARP/NDP lifetime | Negative: desired ownership is rechecked before bursts and remove/add paths are RG-scoped.
- `pkg/daemon/daemon_health.go` | health | compile/bootstrap observability, neighbor refresh | Negative: failures are latched and refresh is rate-limited.
- `pkg/daemon/daemon_ipmon.go` | routing/PBR | overlay publication, FRR order, HA gate | Negative: publish precedes FIB bump and hard FRR error prevents publication.
- `pkg/daemon/daemon_ipmon_test.go` | routing/PBR tests | overlays, link-local, cancellation, HA | Negative: stale overlays are filtered against incoming config and duplicate publish is suppressed.
- `pkg/daemon/daemon_ipsec_apply_test.go` | IPsec | apply error propagation | Negative: swanctl/render failure reaches commit result.
- `pkg/daemon/daemon_ipsec_rebind.go` | IPsec | DHCP rebind retry, health, shutdown | Negative: failures arm bounded retries and success/shutdown clears state.
- `pkg/daemon/daemon_ipsec_rebind_4899_test.go` | IPsec tests | retry/recovery/nonfatal DHCP | Negative: retry health and lease callback behavior are covered.
- `pkg/daemon/daemon_linkstate_monitor_3950_test.go` | netlink | ENOBUFS resubscribe, cancellation | Negative: event loss causes resubscribe and normal events still stream.
- `pkg/daemon/daemon_lldp_reconcile_test.go` | LLDP | manager identity, day-2 lifecycle | Negative: add/remove and unchanged hash behavior are covered.
- `pkg/daemon/daemon_login_chown_5026_test.go` | login | argv injection | Negative: `--` protects chown and unsafe names are rejected.
- `pkg/daemon/daemon_login_optinjection_5005_test.go` | login | option injection | Negative: unsafe usernames are skipped and commands use end-of-options.
- `pkg/daemon/daemon_natpoolalarm.go` | NAT observability | sampler publication, shutdown | Negative: monitor starts only after dataplane arm and is discarded on rollback.
- `pkg/daemon/daemon_natpoolalarm_race_test.go` | NAT tests | pointer publication/race | Negative: boot and rollback pointer lifecycle is covered.
- `pkg/daemon/daemon_neighbor.go` | routing/HA | target collection, bounded probes, concurrency | Negative: periodic phases use in-flight guards and do not block each other.
- `pkg/daemon/daemon_neighbor_listener.go` | routing/HA | NUD parsing, event loss, hot-path cost | Negative: composite failed states are excluded, per-event work uses cached indexes, and probe count is capped.
- `pkg/daemon/daemon_neighbor_listener_test.go` | neighbor tests | NUD matrix/event types | Negative: publishable/unusable transitions and composite states are covered.
- `pkg/daemon/daemon_networkd_apply_test.go` | interfaces | stale sweep, lifeline, failure | Negative: empty managed set still sweeps while preserving lifeline; write error fails commit.
- `pkg/daemon/daemon_nft.go` | host inbound/lo0 | kernel truth table, IPv4/6, interface overrides, Junos-host, fragments | F-03: explicit lo0-first kernel priority contradicts Rust host-inbound-first local delivery. Coarse/fine drop ordering otherwise remains fail-closed.
- `pkg/daemon/daemon_policy_default_4342_test.go` | sessions/policy | default sentinel invalidation | Negative: permit/deny/reject and log-only rematch directions are covered.
- `pkg/daemon/daemon_policy_invalidate.go` | sessions/policy | deletion/rematch/default/scheduler, HA deletes, errors | F-02: enumerate/delete errors are logged but cannot fail the commit; documented ID-0 exclusion is a prior known gap.
- `pkg/daemon/daemon_policy_invalidate_test.go` | sessions tests | deletion, ID-0 compatibility, enumeration errors | F-02: test requires only an error log and partial clear, confirming no caller-visible failure.
- `pkg/daemon/daemon_policy_modified_4234_test.go` | sessions tests | match/action set diff | F-02: modified-policy coverage includes partial enumerate observation but no fail-closed commit outcome.
- `pkg/daemon/daemon_policy_scheduler_4343_test.go` | sessions/scheduler | active-to-inactive invalidation | Negative: tightening transition clears IPv4/IPv6 sessions under rematch; activation does not over-clear.
- `pkg/daemon/daemon_proxyarp.go` | NAT/neighbor | interface identity, stale sweep, periodic locking | Negative: VLAN/RETH resolve to correct netdev and reassert holds apply semaphore.
- `pkg/daemon/daemon_proxyarp_orphan_4955_test.go` | proxy ARP tests | prior-interface sweep | Negative: removed interfaces are fed into teardown.
- `pkg/daemon/daemon_proxyarp_test.go` | proxy ARP tests | VLAN/RETH, family diff, serialization | Negative: enable/remove/reassert behavior and commit serialization are covered.
- `pkg/daemon/daemon_ra.go` | IPv6/HA | PD merge, source LL, RETH identity | Negative: configs are cloned, units are deterministic, and active RETH uses stable link-local.
- `pkg/daemon/daemon_reth.go` | HA interfaces | rename/MAC cycle, DAD/link-local | Negative: link is restored up on success/failure paths and configured link-local is preserved.
- `pkg/daemon/daemon_reth_rename_up_test.go` | RETH tests | failed rename/MAC cycle | Negative: link-up postcondition is covered.
- `pkg/daemon/daemon_rpm.go` | routing/PBR | config hash, pin replacement, retry lifetime | Negative: new+old pin union is held across replacement and failures retry without commit.
- `pkg/daemon/daemon_rpm_test.go` | RPM tests | hash sensitivity, partial failure, retry | Negative: pin installer absence and eventual recovery are covered.
- `pkg/daemon/daemon_run.go` | daemon lifecycle | startup/shutdown, session sync, dataplane arm, HA order | Negative: GC delete sync, event-stream fallback, helper startup, and shutdown joins were traced; F-01 handoff originates in sync callback, not startup wiring.
- `pkg/daemon/daemon_run_test.go` | shutdown | HA update deadline | Negative: shutdown cannot block indefinitely on HA update.
- `pkg/daemon/daemon_scheduler.go` | policy scheduler | snapshot seed, epoch, retry, locks | Negative: initial state is seeded before apply and live republish failures retry with health metrics.
- `pkg/daemon/daemon_scheduler_republish_3780_test.go` | scheduler tests | error propagation, health latch | Negative: runtime update error is preserved and metric clears on recovery.
- `pkg/daemon/daemon_scheduler_test.go` | scheduler tests | context, hash identity, publication | Negative: unchanged schedulers are retained and daemon context governs worker lifetime.
- `pkg/daemon/daemon_snmp_hash_clients_5105_test.go` | SNMP | authorization hash | Negative: client authorization changes invalidate the reconcile hash.
- `pkg/daemon/daemon_snmp_reconcile.go` | SNMP | auth ordering, listener swap, counters | Negative: authorization reconciles before dataplane abort and failed bind remains retryable.
- `pkg/daemon/daemon_snmp_reconcile_test.go` | SNMP tests | enable/disable/auth/traps/overflow | Negative: day-2 lifecycle, retry, and counter clamping are covered.
- `pkg/daemon/daemon_ssh_test.go` | SSH | render validation, atomic revert, hardening | Negative: invalid config never reloads and failed reload restores/removes prior content safely.
- `pkg/daemon/daemon_sudoers_reconcile_3889_test.go` | sudo | downgrade/removal sweep | Negative: stale grants are revoked, including all-users-removed.
- `pkg/daemon/daemon_sudoers_username_4895_test.go` | sudo | filename/argv injection | Negative: unsafe names are rejected.
- `pkg/daemon/daemon_system.go` | host services | logging callbacks, login, SSH, NTP, file atomicity | Negative: reviewed secret handling, argv construction, atomic managed files, and callback swaps; no lane finding.
- `pkg/daemon/dataplane_boot_test.go` | dataplane | backend selection | Negative: retired backends fail explicitly and userspace is the only runtime path.
- `pkg/daemon/deferred_mac_reapply_5134_test.go` | dataplane/RETH | deferred worker debt | Negative: failed post-MAC reapply records retry debt.
- `pkg/daemon/device_map.go` | device identity | preflight, management protection, teardown | Negative: topology/enum failure fails closed and durable markers remain on incomplete teardown.
- `pkg/daemon/device_map_preflight_failclosed_5490_test.go` | device map tests | enumeration failure, fast path | Negative: active maps fail closed; inactive fast path remains no-op.
- `pkg/daemon/device_map_rename_err_4956_test.go` | device map tests | rename/reload errors | Negative: errors propagate rather than claiming success.
- `pkg/daemon/device_map_startup_test.go` | device map tests | startup activation | Negative: naming activation follows explicit config state.
- `pkg/daemon/device_map_teardown_failclosed_5309_test.go` | device map tests | marker retention, idempotence | Negative: failed teardown retains retry state and reaches commit error.
- `pkg/daemon/device_map_test.go` | device map tests | collisions, remap, lifeline | Negative: management strand and collision matrices are covered.
- `pkg/daemon/dhcp_nexthop_resolver_test.go` | DHCP/routing | lease interface identity | Negative: DHCP client key and next-hop resolver use the same Linux name.
- `pkg/daemon/dhcp_recompile_test.go` | DHCP/apply | management lease recompile | Negative: only lease changes that affect managed routing trigger full recompile.


## A7-b2


| Assigned file | Review and substantive negative result |
|---|---|
| `pkg/daemon/dhcp_reconcile_test.go` | Read lifecycle/default/nil-manager/lease-change cases; client replacement and stop behavior are bounded and lease refresh does not restart unchanged clients. No stale client or widened host admission survived. |
| `pkg/daemon/direct_announce_test.go` | Checked immediate and scheduled HA announcements plus cancellation; generation/ownership gates stop future bursts and timers are bounded. |
| `pkg/daemon/direct_garp_gate_test.go` | Checked abdication during follow-ups and sequence transitions; stale owners stop ARP/NA emission. No neighbor-cache poisoning residual beyond covered gates. |
| `pkg/daemon/direct_garp_probe_target_test.go` | Checked sender/target arithmetic across prefixes; probes remain in-subnet and do not select a foreign gateway. |
| `pkg/daemon/direct_vip_ownership_test.go` | Checked desired ownership and stale VIP removal without an edge event; inactive RGs do not retain local-address admission. |
| `pkg/daemon/exec_timeout.go` | Traced both command helpers; fixed argv, 15-second context, `WaitDelay`, stdin and combined output bound apply-time subprocess lifetime. |
| `pkg/daemon/failover_commit_ready_test.go` | Checked settle wait, timeout, epoch supersession, and stable desired-state completion; promotion readiness fails closed on changed intent. |
| `pkg/daemon/frr_failclosed_boot_test.go` | Checked cold/restart compile failures, XDP pin/armed probes, nil manager, and degraded clear; unarmed boot removes stale FRR while live forwarding avoids false withdrawal. |
| `pkg/daemon/frr_fullconfig_guard_test.go` | Read assembler-only guard; production `FullConfig` creation remains centralized, preventing partial applies from erasing route overlays. |
| `pkg/daemon/hb165_bootstrap_batch_test.go` | Checked device-map strand detection, off-target controls, bootstrap commit, node ID parsing, and import record; unsafe management renames reject before apply. |
| `pkg/daemon/heartbeat_retry_ctx_test.go` | Checked pre-start and mid-retry cancellation; retry sleeps and goroutines terminate on context cancellation. |
| `pkg/daemon/host_inbound_addressless_3698_test.go` | Checked transition reporting for addressless enforcing zones. The known transient addressless gap is observable and deduplicated; no new silent widening was found. |
| `pkg/daemon/host_inbound_ambiguous_3718_test.go` | Checked ambiguity enter/exit reporting; strict validation is the admission guard and tolerant ambiguity remains visible. No new order-dependent root beyond prior dedup. |
| `pkg/daemon/host_inbound_icmp_degenerate_4813_test.go` | Checked empty/degenerate ICMP tuples and valid successors under timeout; renderer terminates and malformed tuples do not become wildcard accepts. |
| `pkg/daemon/host_inbound_junos_host_4146_test.go` | Checked iifname scoping, address subtraction, IKE exemption, unrepresentable applications, nft parsing, Rust-oracle parity, and rule order; deny programs remain source-zone scoped. |
| `pkg/daemon/host_inbound_nft_test.go` | Read all service/protocol/family/lifeline/default-deny/IPsec/error and ident-reset cases; atomic apply/delete errors surface and recognized permits retain a terminal deny. |
| `pkg/daemon/host_inbound_parity_test.go` | Checked token-domain SSOT, BFD/SIP/TFTP/routing mappings, ident reset, and empty stanza; kernel and classifier domains agree without a blanket protocol-all permit. |
| `pkg/daemon/host_inbound_per_iface_3362_test.go` | Checked exact-interface override scoping and counter declaration uniqueness; sibling interfaces do not inherit permits in the ordinary single-owner case. Known conflicting-owner merge root suppressed. |
| `pkg/daemon/host_inbound_ssot_render_3627_test.go` | Checked byte-identical L4 rendering and reject-marker/verdict parity; no independent kernel/classifier token drift found. |
| `pkg/daemon/host_inbound_unzoned_4420_test.go` | Checked addressed unzoned deny and no-zone control; unzoned local addresses drop when zone enforcement exists without globally denying a zone-free appliance. |
| `pkg/daemon/host_tunables.go` | Read all capture/apply/restore paths; first-capture wins, failed restores retain debt, writes are configuration-time and path-bounded, and no numeric truncation or shared-map race survived. |
| `pkg/daemon/host_tunables_daemon.go` | Traced opt-in transitions, userspace disable, shutdown serialization, coalescence and neighbor restoration; host-global knobs remain gated and apply is serialized against restore. |
| `pkg/daemon/host_tunables_restore_applysem_4691_test.go` | Checked shutdown blocking on `applySem`; mutable capture maps are not iterated concurrently with an apply. |
| `pkg/daemon/host_tunables_restore_debt_5114_test.go` | Checked failed governor/budget/neighbor restoration and successful release; failed fields remain owned for retry rather than being falsely marked restored. |
| `pkg/daemon/host_tunables_restore_test.go` | Checked opt-in/off transitions, coalescence-only operation, shutdown restore, VM heuristic, and capture idempotence; original host values are preserved. |
| `pkg/daemon/host_tunables_test.go` | Read governor, budget, neighbor, error, default and restore cases; partial writes continue without fabricating success and work is bounded by discovered CPUs/interfaces. |
| `pkg/daemon/interface_addr_test.go` | Checked cluster bind selection including link-local IPv6 exclusion; fallback does not bind an unusable control address. |
| `pkg/daemon/ipsec_lease_rebind_test.go` | Checked DHCP local-address rerender and irrelevant-lease no-op; bound gateways reapply through the retry-debt path and unrelated leases do not churn SAs. |
| `pkg/daemon/ipsec_sa_sync_empty_4385_test.go` | Checked empty-set advertisement, force resend, and missed-empty retry; tunnel-down state is authoritative and cannot resurrect stale peer SAs. |
| `pkg/daemon/ipv6_static_nexthop_test.go` | Checked global/VRF, deterministic tie-break, link-local ambiguity/qualifier, VRRP VIP and IP-monitor overlays; inferred scope remains table- and interface-correct. |
| `pkg/daemon/kernel_selfrecover.go` | Read boot hold and recovery loop; promotion marker must match the running kernel, candidate ambiguity keeps SECONDARY, and tick/context resources are bounded. |
| `pkg/daemon/legacy_dataplane_canary_synthetic_test.go` | Checked scanner false positives, selectors, calls, comments/strings and per-line dedup; retired dataplane references remain mechanically blocked without unbounded parsing. |
| `pkg/daemon/legacy_dataplane_canary_test.go` | Checked repository canary and accessor removal; no legacy forwarding path can be silently reselected from this slice. |
| `pkg/daemon/linksetup.go` | Read PCI enumeration, collision breaking, persistent link files, rename rollback, RSS reapply and reload timeout; operations are cold-path and errors remain explicit. |
| `pkg/daemon/linksetup_collision_4178_test.go` | Checked enumeration shifts, first boot and steady state; temporary renames avoid corrupting another NIC's persistent identity. |
| `pkg/daemon/linksetup_rename_test.go` | Checked lookup/down/rename/up failures and rollback; links are restored/up where possible and actionable failures propagate. |
| `pkg/daemon/lo0_filter_test.go` | Read all nft payload, family/address, protocol, port, fragment, TCP flag, action, logging and counter cases; malformed constraints fail closed and apply/delete errors reach commit. |
| `pkg/daemon/login_deprovision_5128_test.go` | Checked credential revocation and provenance scoping; only xpf-provisioned users are locked and removed users retain retry intent on failure. |
| `pkg/daemon/login_emptied_keys_5106_test.go` | Checked managed key removal, foreign account preservation, and idempotence; an empty configured key set does not preserve stale xpf trust. |
| `pkg/daemon/login_passwd_failclosed_5493_test.go` | Checked passwd/shadow read errors versus genuine absence; database uncertainty retains markers and does not abandon credential revocation. |
| `pkg/daemon/login_password.go` | Traced password action, UID/GID tri-state, provenance, root/user key paths, and deprovision sequence; commands are fixed-argv/time-bounded and marker removal follows successful revocation. |
| `pkg/daemon/login_password_functional_test.go` | Checked functional account provisioning/authentication boundary; no command-option injection or false success surfaced. |
| `pkg/daemon/login_password_test.go` | Checked hash actions, lock detection, marker containment, shadow parsing, apply revalidation and lookup helpers; stale hashes are re-read before mutation. |
| `pkg/daemon/mgmtvrf_race_test.go` | Checked pre-publication and concurrent publication; management VRF interface snapshots do not race readers. |
| `pkg/daemon/mgmtvrf_route_reconcile_5108_test.go` | Checked withdrawn/all route deletion, ESRCH tolerance and canonical keys; stale management routes are removed without treating already-absent routes as failure. |
| `pkg/daemon/neighbor_periodic_guard_test.go` | Checked nonblocking dispatch, wedged phase cadence and age metrics; periodic work is single-flight and does not accumulate unbounded goroutines. |
| `pkg/daemon/nft_chain_priority_test.go` | Checked distinct ordered lo0 and host-inbound hook priorities; lo0 terminal policy precedes host-inbound without accidental shadowing. |
| `pkg/daemon/ntp_test.go` | Checked source rendering, threshold bounds, and managed-file removal; invalid thresholds do not reach chrony and empty config tears down owned state. |
| `pkg/daemon/per_rg_test.go` | Read ownership modes, multi-RG state, nil config entries, zone map, VRID mapping and reconciliation; ordinary per-RG state remains isolated. Day-2 mode-toggle root is deduplicated. |
| `pkg/daemon/per_rg_zoneid_3704_test.go` | Checked stable zone-ID keying; peers derive symmetric RG ownership independent of config ordering. |
| `pkg/daemon/persistent_snat_apply_test.go` | Checked required-protocol mismatch in strict and lenient wrappers; strict commit aborts publication while compatibility apply keeps the dataplane disarmed rather than widening NAT. |
| `pkg/daemon/policy_scheduler_apply_test.go` | Checked compile abort cleanup, previous-state preservation, non-userspace sink, seeding and update paths; scheduler state is not promoted ahead of validated policy. |
| `pkg/daemon/ra_source_test.go` | Checked stable RETH link-local, explicit source precedence, units and non-mutation; RA source selection remains interface-local. |
| `pkg/daemon/resolve_neighbor_test.go` | Checked Junos/Linux unit naming, VLAN resolution and standby scheduling; ambiguous names do not select an unrelated neighbor target. |
| `pkg/daemon/rg_state.go` | Read mutex/epoch/apply-pending/log gates and strict/default formulas; transition state is race-safe and stale applies reject. Existing SetStrictVIPOwnership recompute gap is prior root. |
| `pkg/daemon/rg_state_test.go` | Read every transition, posture-delay, strict ownership, retry-log and stale-epoch case; tests cover ordinary concurrency invariants but explicitly require a later reconcile after mode toggle, matching dedup. |
| `pkg/daemon/rollback_resync_test.go` | Checked peer-present/absent rollback publication; rollback resync is attempted without making peer absence a local false denial. |
| `pkg/daemon/rollback_serialize_test.go` | Checked apply semaphore, timer once-only behavior, and store/apply consistency; rollback cannot interleave a competing commit. |
| `pkg/daemon/root_auth_revoke_5276_test.go` | Checked stanza/password/key removal, foreign key preservation and idempotence; removing one factor revokes only managed material while full removal closes both. |
| `pkg/daemon/rss_indirection.go` | Read allowlist, mlx5 gate, parse bounds, default restore and weight apply; hash-key parsing is bounded and errors do not touch foreign NICs. Degenerate in-range idempotence is prior root. |
| `pkg/daemon/rss_indirection_test.go` | Read all worker/queue, driver, allowlist, parse, restore and idempotence cases; transition restore is covered. Range-only match acceptance is explicitly deduplicated. |
| `pkg/daemon/runtime_probes.go` | Read narrow dataplane/API/CLI interfaces; probes expose only required methods and do not add shared ownership or unsafe conversions. |
| `pkg/daemon/runtime_probes_test.go` | Checked compile-time interface assertions; production managers satisfy the intended narrow contracts without legacy fallback. |
| `pkg/daemon/session_sync_readiness_test.go` | Checked disconnect/reconnect, timeout, inbound progress, ACK and cold start; readiness clears on uncertainty and only bounded fallback relaxes priming. |
| `pkg/daemon/ssh_known_hosts_clear_5112_test.go` | Checked managed file removal, foreign file preservation, write and absent idempotence; empty trust config removes only xpf-owned state. |
| `pkg/daemon/startup_goodbye_5093_test.go` | Checked retry debt, success completion and in-flight serialization; failed goodbye work remains pending instead of claiming teardown success. |
| `pkg/daemon/syslog_close_3579_test.go` | Checked superseded/event-mode stream closure; removed clients stop delivery and release resources. |
| `pkg/daemon/syslog_reconcile_5111_test.go` | Checked final/partial removal, write and no-op; generated rsyslog drop-ins converge without deleting unrelated destinations. |
| `pkg/daemon/syslog_severity_5314_test.go` | Checked emergency/critical and merged thresholds; severity selection does not invert into send-all. |
| `pkg/daemon/syslog_source_test.go` | Checked v4/v6 primary, unit zero, absence and unknown interface; source binding does not silently choose another interface. |
| `pkg/daemon/syslog_teardown_3351_test.go` | Checked zero-stream teardown and nil safety; stale clients are closed and repeated teardown does not panic. |
| `pkg/daemon/system/dns.go` | Read resolved/resolv.conf render and domain dedup; output is deterministic, line-oriented and bounded by configured inputs. |
| `pkg/daemon/system/dns_test.go` | Checked static/DHCP nameservers, search domains and empty input; no false resolver directive or stale content behavior surfaced. |
| `pkg/daemon/system_dns_nameserver_belt_5010_test.go` | Checked injected and valid nameservers; malformed line-bearing values are removed while valid family addresses remain. |
| `pkg/daemon/system_string_injection_belt_4902_test.go` | Checked chrony, SSH algorithms and DNS domains; control characters cannot add generated service directives. |
| `pkg/daemon/time_zone_symlink_belt_5011_test.go` | Checked valid containment and traversal rejection; timezone symlink targets cannot escape zoneinfo. |
| `pkg/daemon/tunnel_anchor_test.go` | Checked userspace/default/legacy mode, WireGuard, MTU, RI membership and per-unit names; route anchors preserve intended kernel identity. |
| `pkg/daemon/userspace_sync_test.go` | Read v4/v6 conversion, byte order, NAT aliases, ownership gates, readiness, batching, event wiring and nil fallback; session publication remains RG/fabric scoped and bounded. |
| `pkg/daemon/vip_readiness_test.go` | Checked link/carrier/absence/RG/no-VIP and no-RETH takeover paths; ownership fails closed until required VIP interfaces are ready. |
| `pkg/daemon/web_management_clamp_4047_test.go` | Checked loopback recognition and bind clamping; tolerant/off-loopback management addresses are forced local. |
| `pkg/daemon/zoneid_ha_symmetry_test.go` | Checked stable SSOT and earlier-zone insertion; HA zone IDs remain deterministic across peers. |
| `pkg/frr/bgp_neighbor_ip_guard_4588_test.go` | Checked received/advertised/detail invalid IP rejection and valid v4/v6 pass-through; operational input cannot inject vtysh commands. |
| `pkg/frr/bgp_policy_chain_5277_test.go` | Checked import/export composition, ordering, explicit reject, global defaults, single-policy stability and collision failure; no policy is dropped or merged by alias. |
| `pkg/frr/bgp_remote_as_2963_test.go` | Checked AS0 declaration suppression; malformed peers are absent from the base neighbor stanza. |
| `pkg/frr/bgp_remoteas0_activate_bfd_5518_test.go` | Checked the full managed section; AS0 peers are also absent from AF activation and BFD, closing the prior partial-filter root. |
| `pkg/frr/bgp_summary_3942_test.go` | Checked v4/v6, established/down and empty JSON summaries; parser does not fabricate peers or collapse families. |
| `pkg/frr/config_render.go` | Read static/negative/ECMP/DHCP/backup/cluster/preferred rendering and ECMP resolution; route renderability and DHCP suppression share one predicate, and table/VRF identity is preserved. |
| `pkg/frr/dhcp_default_suppression_5519_test.go` | Checked v4/v6 empty, next-hop, discard and reject defaults; only a static route that installs a FIB entry suppresses DHCP fallback. |
| `pkg/frr/executor_test.go` | Checked executor injection, primary reload, additive fallback, hard failure and zero-value manager; errors and degraded state remain visible. |
| `pkg/frr/fbf_table_render_test.go` | Checked forwarding-instance table suffixes for static and preferred routes; PBR routes are not leaked into the master table. |
| `pkg/frr/frr_clusterid_origin_render_4919_test.go` | Checked invalid cluster ID and origin values; malformed tolerant-load values are skipped rather than poisoning the entire FRR reload. |
| `pkg/frr/frr_test.go` | Read the complete 6k-line render/manager/parser suite: static/VRF/DHCP, protocols, BFD, policy terms, families, auth, injection, managed-section atomicity and route JSON. No new cross-composition defect survived. |
| `pkg/frr/frrconf_mode_4484_test.go` | Checked fresh 0640 mode, operator-mode preservation and owner decision; routing secrets are not newly world-readable and existing ownership is not restamped. |
| `pkg/frr/manager.go` | Traced write+reload lock, atomic managed section, marker repair, fallback/retry generation, Stop and Clear; hard and additive failures arm debt, stale retries cannot clear newer degradation. |
| `pkg/frr/manager_reload_test.go` | Checked retry convergence/cancel/stop, stale success, missing pytools, disabled retry and hard-failure recovery; retry episodes are single-flight and lifecycle-bound. |
| `pkg/frr/policy_as_path_prepend_2892_test.go` | Checked ordered prepend and empty control; rendering neither drops ASNs nor emits an empty invalid clause. |
| `pkg/frr/policy_default_action_2998_test.go` | Checked BGP default accept, redistribute default reject, explicit reject and route-map collection; context-specific terminal actions stay explicit. |
| `pkg/frr/policy_injection_4097_test.go` | Checked newline/control sanitization in policy output; tolerant values cannot create sibling FRR directives. |
| `pkg/frr/policy_redist_alias_collision_5116_test.go` | Checked collision refusal and noncollision byte stability; lenient policy names cannot merge a fail-closed redistribution alias. |
| `pkg/frr/policy_render.go` | Read protocol and route-map lowering, valid-neighbor reuse, defined-policy filtering, composed chains, family split, collision guards and sanitizer use; malformed references skip/fail closed without permit-all dangling maps. |
| `pkg/frr/policy_routemap_leak_4481_test.go` | Checked cross-context defaults; BGP permit fallthrough cannot widen IGP redistribution because a distinct deny-default alias is emitted. |
| `pkg/frr/policy_setclause_injection_4482_test.go` | Checked set clauses and prefix-list values; all rendered free-text slots stay line-contained. |
| `pkg/frr/preferred_routes_test.go` | Checked preferred-only/full/link-local scope; failover overlays retain distance 1 and required egress qualification. |
| `pkg/frr/route_detail_perfamily_5125_test.go` | Checked v4/v6 command failure, JSON parse failure and dual success; partial data and joined errors reach callers instead of false empty success. |
| `pkg/frr/router_id_2980_test.go` | Checked invalid router ID suppression; malformed IDs cannot poison all routing updates on tolerant load. |
| `pkg/frr/routing_adjacency_4285_test.go` | Checked OSPF timers/priority and BGP source/passive/hold/local-AS; adjacency knobs remain scoped to the intended peer/interface. |
| `pkg/frr/static_ecmp_list_3872_test.go` | Checked bracket-list ECMP; every next hop renders at equal distance without collapsing to the first. |
| `pkg/frr/static_empty_route_3872_test.go` | Checked zero-next-hop no-op and explicit discard; incomplete routes do not become accidental blackholes. |
| `pkg/frr/static_floating_3871_test.go` | Checked qualified distance and plain-list ECMP; backup preference remains per next hop and does not narrow primaries. |
| `pkg/frr/static_reject_5298_test.go` | Checked compiler-to-render reject/discard shape; reject installs unreachable while discard installs Null0, avoiding default-route fallthrough. |
| `pkg/frr/status_parse.go` | Read RIP/ISIS/OSPF/BGP parsing, bounded BGP streaming, per-family route detail and formatter; scanner/process resources are bounded and query/parse errors propagate. |
| `pkg/frr/testseam.go` | Checked injected executor construction and marker export; test substitution is scoped and does not alter production defaults. |
| `pkg/frr/vtysh.go` | Read command, stream, process-group reload and additive load execution; IP selectors validate, contexts/WaitDelay bound children, and output tails are capped. |

Cross-file negative result: host-local traffic is enforced in ordered lo0 then host-inbound nft chains, with interface/address/family scoping, terminal default denial, explicit IPsec/control-message exemptions, and error propagation through `errors.Join`. Routing applies write one atomic managed section, serialize reloads, and retain retry debt after hard or additive failure. Static reject/discard and DHCP fallback preserve both false-admission and false-denial intent. IPsec apply/rebind/empty-SA synchronization failures remain visible and retryable. Configuration-sized maps/slices and bounded subprocesses are outside the packet hot path; no unsafe memory, integer truncation, unbounded goroutine/process growth, or new vSRX parity defect survived.


## A7-b3


Every assigned path is listed. `C` denotes correctness/fail-closed behavior, `P` policy or vSRX effect, `R` resource/concurrency/bounds, and `T` tests. Each entry records a substantive negative result or a deduplicated root.

### IPsec

- `pkg/ipsec/childname_collision_5122_test.go` - C/P/T: pins deterministic child-name disambiguation for sanitized collisions and selector expansion; no child overwrite or cross-VPN selector admission remains.
- `pkg/ipsec/crypto.go` - C/R: Junos `$9$` decoding rejects malformed alphabet, skip, and incomplete nibble shapes with bounded linear work; no panic, truncation acceptance, or plaintext logging found.
- `pkg/ipsec/delete_terminate_3941_test.go` - C/P/T: covers successful reload before removed-SA termination, list failure fallback, idempotence, and empty clear; teardown failure remains observable in logs but is an already-reviewed availability posture.
- `pkg/ipsec/dhcp_rebind_test.go` - C/P/T: DHCP-bound gateway scoping and current-address re-render are pinned; daemon `applySem` serializes this path with commits, so config-file and connection-set races were refuted.
- `pkg/ipsec/dhgroup_roundtrip_test.go` - C/P/T: strict parser-to-typed-to-swanctl DH group 14 round trip produces `modp2048`; no numeric/token drift found.
- `pkg/ipsec/ike.go` - C/P/R: proposal/auth/DH normalization, named-reference fallback, DPD derivation, SA parsing, initiate/terminate subprocess bounds, and status parsing were traced. Unknown IKE chains skip rather than negotiate defaults; the deliberate tolerant ESP fallback and skipped-VPN SA root are already indexed.
- `pkg/ipsec/ike_chain_failclosed_test.go` - C/P/T: distinguishes absent policy intent from dangling IKE chains and ensures unresolved chains omit the VPN; no downgrade-to-default regression found.
- `pkg/ipsec/ike_proposals_multivalue_3904_test.go` - C/P/T: all resolvable IKE/ESP proposal values render in stable order while dangling-only sets fail conservatively; no first-value loss remains.
- `pkg/ipsec/ipsec_test.go` - C/P/R/T: broad proposal, identity, secret, DPD, SA parser, family/address, selector, and rendering coverage passed; malformed values do not broaden selectors or crypto.
- `pkg/ipsec/manager.go` - C/P/R: atomic config writes, 15-second subprocess bounds plus wait delay, successful-load-gated connection promotion, removed-SA diffing, and unconditional teardown fallback were traced. Daemon callers serialize whole applies; no manager state race survives that caller guard.
- `pkg/ipsec/manager_reload_ordering_4898_test.go` - C/P/T: failed load preserves prior names and SAs, and a later successful retry performs the deferred diff; no premature teardown or forgotten removal found.
- `pkg/ipsec/matchfamily_linklocal_test.go` - C/P/T: IPv4, global IPv6, and scoped link-local family matching are pinned; zone qualification is retained where required.
- `pkg/ipsec/policy.go` - C/P/R: sorted rendering, exact rendered-name set, gateway/PSK/identity escaping, child collision handling, traffic selectors, DHCP/kernel address resolution, bounded DNS concurrency, and family selection were traced. Unrenderable VPN behavior is duplicate-suppressed below.
- `pkg/ipsec/proposalset_ah_hb167_test.go` - C/P/T: proposal-set expansion renders ESP values and rejects/omits unsupported AH instead of fabricating ESP semantics.
- `pkg/ipsec/reload_error_4433_test.go` - C/P/T: swanctl load errors propagate to apply; no successful commit is reported by this manager on failed activation.
- `pkg/ipsec/swanctl_render_test.go` - C/P/R/T: extensive exact-output coverage pins quoting, identities, proposals, lifetimes, DPD, route-based interface IDs, selectors, and malformed-reference handling; generated values cannot inject settings lines.
- `pkg/ipsec/trafficselector_render_4098_test.go` - C/P/T: configured local/remote traffic selectors replace broad defaults and preserve multiple children; no selector widening found.
- `pkg/ipsec/unrenderable_terminate_5494_test.go` - C/P/T: an omitted connection leaves the loaded set only after successful reload and is then terminated. The residual terminate-failure/stale-SA posture is the indexed `Successfully skipped VPNs retain established IPsec SAs` root and was not re-reported.

### Networkd

- `pkg/networkd/networkd.go` - C/P/R: protected management files, external ownership, expected-file construction, stale sweep, atomic writes, reload and reconfigure debt, bounded `networkctl`, family-specific DHCP address suppression, rp_filter restoration, and clear behavior were traced. Reconfigure remains retryable and visible; the clear/debt variant is already owned by `#4954`.
- `pkg/networkd/networkd_test.go` - C/P/T: generated bond/bridge/link/network units, ownership, address ordering, DHCP family gates, external files, stale cleanup, and write-if-changed behavior are covered; no directive-injection or opposite-family address loss remains.
- `pkg/networkd/reload_debt_4954_test.go` - C/P/T: failed reload and reconfigure are retried on byte-identical apply and debt clears only after success. The related `Clear` no-file candidate is the same indexed activation-debt root.
- `pkg/networkd/rpfilter_test.go` - C/P/T: per-device zero restore, missing TUN tolerance, host-global override warning, and parse/read failures are covered; this best-effort knob does not falsely report policy enforcement.
- `pkg/networkd/stale_remove_4900_test.go` - C/P/T: stale removal failure is returned and successful removals still trigger reload; no silently surviving removed unit is reported as a clean apply.

### Routing and host integration

- `pkg/routing/bond.go` - C/P/R: desired signature, adoption, partial member realization, recreate/delete, ownership retention, and clear errors were traced. The partial-member signature defect is already indexed as `Bond partial member failure is recorded as a completed signature` and was suppressed.
- `pkg/routing/bond_test.go` - C/R/T: create/adopt/reuse, member completion, changed signatures, stale deletion, clear, and netlink errors are broadly pinned; no separate ownership or resource leak survived.
- `pkg/routing/iface_reuse_test.go` - C/P/T: tunnel, XFRM, bond, and VRF adoption/replacement retain type/parameter checks; incompatible existing links do not become trusted desired state.
- `pkg/routing/monitor.go` - C/P/R: operational carrier state and copied status snapshots are correct for found links. Missing/transient link lookup is omitted and can preserve HA weight, but that exact root is indexed as `Missing local interface monitor retains healthy election weight`; replacement debt is likewise indexed.
- `pkg/routing/monitor_test.go` - C/P/T: admin-up/carrier-down, unknown-state fallback, link lookup, and copied status behavior are covered; missing-local fail-open coverage is absent but duplicate-suppressed with the production root.
- `pkg/routing/probe_pin.go` - C/P/R: deterministic bounded mark/table assignment, RETH/interface resolution, rule-before-route programming, rollback, startup band clear, and per-test failure propagation were traced. Failed pins hold RPM state rather than probing the default path; stale item-delete failures are bounded to reserved probe-only state.
- `pkg/routing/probe_pin_test.go` - C/P/T: deterministic assignments, same target over two uplinks, IPv4/IPv6 routes, install failures, rollback, list failures, and stale clear are covered; no transit-route exposure found.
- `pkg/routing/reth.go` - C/P/R: only stale `reth*` links that are actual bonds are deleted; non-bond name collisions are retained. Link deletion errors are logged, a known stale-cleanup availability posture with no new root.
- `pkg/routing/routeformat.go` - C/P/R: terse, destination, summary, protocol and Junos table formatting are finite and preserve reject/discard/ECMP meanings; no action inversion or request-amplified loop found.
- `pkg/routing/routes.go` - C/P/R: per-family dumps, table/VRF resolution, route disposition, ECMP leg projection, link-name fallback, and protocol tags were traced. `GetTableRoutes` discards partial results when either family fails, but this is the already-fixed/indexed partial-route rendering root `git:6412f2a16`, not a new mechanism.
- `pkg/routing/routes_disposition_5410_test.go` - C/P/T: kernel unreachable and blackhole routes display as reject and discard respectively; direct routes remain distinct.
- `pkg/routing/routes_multipath_test.go` - C/P/T: all ECMP next hops, weights, interfaces, and first-leg compatibility fields render; nil legs are safely skipped.
- `pkg/routing/routes_perfamily_5125_test.go` - C/P/T: successful-family partials plus tagged errors are pinned for main/table/all-table reads. The specific-table caller gap is duplicate-suppressed under the same partial-render root.
- `pkg/routing/routing.go` - C/R: façade ownership and delegation were checked; one netlink handle is closed once after keepalive stop. Public close concurrency is explicitly excluded and no daemon caller violates it.
- `pkg/routing/routing_test.go` - C/P/R/T: broad VRF, routes, formats, tunnels, rules, bonds, XFRM, RETH, monitor, and façade tests passed; no independent production decision is hidden in helpers.
- `pkg/routing/rtproto_test.go` - C/P/T: FRR and Linux route protocol values map to stable display/filter names; unknown values remain numeric.
- `pkg/routing/rules.go` - C/P/R: next-table, rib-group, PBR clear/add errors, bounded priority windows, family/table resolution, interface scoping, address/DSCP/L4 predicates, unrepresentable-term fail-closed drops, and degraded reporting were traced. Existing clear-partial and PBR representability roots are indexed; no new widened rule survived.
- `pkg/routing/rules_test.go` - C/P/R/T: clear/list/delete/add failures, caps, families, prefix lists, attachment direction/interface, DSCP, protocol/ports, except predicates, and table resolution are covered; package and race tests passed.
- `pkg/routing/teardown_linkdel_4901_test.go` - C/P/T: tunnel/XFRM/bond deletion errors propagate and ownership remains for retry; no false clean teardown remains.
- `pkg/routing/test_seams.go` - R/T: test-only constructors consistently inject one link/route surface into all submanagers; no production build path or policy fallback is introduced.
- `pkg/routing/tunnel.go` - C/P/R: in-place ownership reconciliation, incompatible-link replacement, address/VRF claims, GRE/IPIP/IP6/WireGuard parameters, MTU, keepalive drain/generation, bounded helper execution, status, and clear retry state were traced. Prior tunnel churn, transient lookup, and stale ownership roots are represented in the dedup index; no new one survived.
- `pkg/routing/tunnel_anchor_keepalive_test.go` - C/P/R/T: anchor adoption/recreate and keepalive generation invalidation prevent an old runner from publishing state for a replacement link.
- `pkg/routing/tunnel_apply_failclosed_5355_test.go` - C/P/T: create, setup, and recreate netlink failures aggregate into apply errors rather than a successful commit.
- `pkg/routing/tunnel_keepalive.go` - C/P/R: raw/ping socket probing validates nonce, peer, sequence and payload under deadlines; unsupported errno classification, nonce generation, and bounded reads were checked. No packet-path allocation or leaked connection found.
- `pkg/routing/tunnel_keepalive_test.go` - C/P/R/T: success, timeout, malformed/foreign replies, unsupported errors, retry transitions, state copies, and sequence wrap are covered.
- `pkg/routing/tunnel_prober_test.go` - C/P/T: source/destination family and zone handling, deadline, nonce, ICMP reply validation, and error classification are pinned.
- `pkg/routing/tunnel_reconcile_test.go` - C/P/R/T: extensive add/change/remove/adopt, address, VRF, WireGuard, transient lookup, ownership retry, keepalive, and clear cases pass; no distinct reconcile hole survived deduplication.
- `pkg/routing/vrf.go` - C/P/R: stable desired map, adoption by type/table, transient lookup ownership retention, orphan reap, creation rollback, bind, and copied tracked state were traced under one mutex; no cross-manager lock cycle or external VRF deletion found.
- `pkg/routing/vrf_stable_tableid_test.go` - C/P/T: same-name table changes recreate, table collisions fail, and stable IDs reuse without churn.
- `pkg/routing/xfrm.go` - C/P/R: deterministic if_id, desired collision detection, adoption by type/if_id, recreate ordering, transient lookup retention, setup errors, stale deletion, and clear are checked under a mutex; malformed/incompatible links never become accepted XFRM state.
- `pkg/routing/xfrm_apply_failclosed_5310_test.go` - C/P/T: genuine create/delete/setup errors fail apply while already-gone cleanup stays idempotent.
- `pkg/routing/xfrm_linkbyname_transient_5461_5495_test.go` - C/P/T: transient lookup errors preserve ownership and retry both desired and removed links; no orphan or duplicate create is acknowledged.


## A8-b1


Dimensions used below: `C` correctness and error semantics; `P` policy/zone allow-deny parity and vSRX behavior; `R` resources, bounds, concurrency, and hot/cold-path cost; `T` tests and modularity. Every assigned path is ledgered.

### API framework, authentication, lifecycle, and diagnostics

- `pkg/api/api.go` - C/R: strict numeric selectors, interface-reference parsing, nil-zone traversal, runtime interfaces, and response helpers were checked; malformed policy/session selectors fail closed and no new widening or bound defect was found.
- `pkg/api/api_ctx_cancel_5232_5233_test.go` - T/R: cancellation reaches dataplane diagnostic and mutation calls; no detached request work remains uncovered in the exercised paths.
- `pkg/api/auth.go`, `pkg/api/auth_consttime_4157_test.go`, `pkg/api/auth_test.go` - C/R/T: Basic/Bearer/API-key gates, constant-time secret comparisons, challenge behavior, and absent/malformed credentials were checked; no authentication bypass or secret-dependent early return was found.
- `pkg/api/crosssite.go`, `pkg/api/crosssite_5055_test.go` - C/T: origin/host canonicalization, preflight, trusted proxy behavior, and WebSocket/SSE-adjacent cross-site gates were checked; no permissive malformed-origin fallback found.
- `pkg/api/exec_timeout.go`, `pkg/api/exec_timeout_test.go` - R/T: command budgets, cancellation, process-group cleanup, and bounded output behavior were checked; no unbounded diagnostic subprocess lifetime found.
- `pkg/api/server.go`, `pkg/api/server_run_leak_5058_test.go` - C/R/T: route registration, auth wrapping, TLS material handling, listener startup rollback, shutdown, and function wiring were checked; no handler exposure or surviving listener/goroutine regression found.
- `pkg/api/diag_concurrency_5057_test.go`, `pkg/api/http_dos_hardening_4150_test.go` - R/T: diagnostic admission limits and HTTP read/header/idle/body constraints are pinned; no obvious unbounded concurrent diagnostic or request-body path found.
- `pkg/api/health.go`, `pkg/api/health_test.go` - C/T: degraded/ready component aggregation and nil dependencies were checked; health does not turn a failed dataplane component into a healthy status.

### Configuration API

- `pkg/api/config.go` - C/R: configure-mode ownership, bounded body reads, commit/activate/load/rollback flows, and secret-safe renderers were traced; mutation errors remain explicit and no partial-success response was found.
- `pkg/api/config_activate_test.go`, `pkg/api/config_commit_test.go`, `pkg/api/config_load_bodycap_hb164_test.go` - T/R: activation/commit failure propagation and the load body cap are covered; no silent commit success or oversized-body acceptance in these paths.
- `pkg/api/config_raw_ast_redaction_test.go`, `pkg/api/config_secret_redaction_test.go`, `pkg/api/show_text_snmp_redact_5315_test.go` - C/T: raw AST, typed configuration, and text-show secret redaction are pinned; no assigned display path exposed the tested credentials.
- `pkg/api/config_rollback_compare_strict_3443_test.go`, `pkg/api/configstore_helper_test.go` - C/T: rollback selectors reject malformed/noncanonical values and test stores use isolated state; no selector widening found.

### Security policy, zones, screens, events, and text projection

- `pkg/api/security.go` - C/P/R: zone and policy inventories, scoped/global/default rows, counters, screens, event filters, and match-policies validation/projection were reviewed end to end. Duplicate/unknown/malformed selectors fail closed and tier/action projection generally follows the shared matcher; the missing ingress-interface dimension causes `A8-b1-F001`.
- `pkg/api/security_test.go`, `pkg/api/security_matchpolicies_action_3375_test.go`, `pkg/api/security_matchpolicies_scope_3331_test.go` - P/T: configured permit/deny/default, global inventory, policy scope, and runtime ID assertions are present; they do not exercise per-interface host-inbound divergence (`A8-b1-F001`).
- `pkg/api/security_matchpolicies_dup_3709_test.go`, `pkg/api/security_matchpolicies_unknownkey_5316_test.go`, `pkg/api/security_matchpolicies_queried_zones_3627_test.go` - C/T: duplicate and unknown keys are rejected before nil-config handling and queried zones are echoed; no malformed-query widening found.
- `pkg/api/security_matchpolicies_exclusion_3668_test.go`, `pkg/api/security_matchpolicies_desc_sched_3685_test.go`, `pkg/api/security_matchpolicies_scheduler_3414_test.go` - P/T: excluded-address meaning, descriptions, and unavailable/inactive scheduler fail-closed behavior are pinned; no opposite-action regression found.
- `pkg/api/security_matchpolicies_hostinbound_3627_test.go`, `pkg/api/security_zone_hostinbound_3328_test.go` - P/T: zone-level and per-interface inventory plus host-inbound token/deny/global-accept projection are tested. The host-inbound match tests use a single effective zone posture and therefore miss mixed interfaces (`A8-b1-F001`).
- `pkg/api/security_default_policy_log_3670_test.go`, `pkg/api/security_policy_addr_inventory_3336_test.go`, `pkg/api/security_policy_scheduler_inventory_3624_test.go` - P/T: default log modes, address exclusion/log metadata, and scheduler inventory state are preserved; no allow/deny inversion found.
- `pkg/api/security_policy_counter_handle_3474_test.go`, `pkg/api/security_policy_id_zero_3623_test.go`, `pkg/api/policies_bulk_reader_test.go`, `pkg/api/policy_counters_test.go` - C/R/T: raw slice indexes, ID zero presence, one bulk snapshot, default sentinel, stats gating, and counter errors are covered; no counter-to-policy misattribution found.
- `pkg/api/security_scoped_global_3286_test.go`, `pkg/api/security_zone_local_3358_test.go`, `pkg/api/security_zone_policy_meta_3329_test.go` - P/T: scoped-global zone sets, authored zone-local names, descriptions, and TCP-RST posture are surfaced; no all-zone widening in the inventory projection found.
- `pkg/api/security_screen_inventory_3327_test.go`, `pkg/api/security_screen_nil_3476_test.go`, `pkg/api/security_zone_nil_3493_test.go` - C/T: screen checks/thresholds and tolerant nil screen/zone/rule slots avoid panic; nil values do not become permit rows.
- `pkg/api/rest_events_forensic_3337_test.go`, `pkg/api/rest_events_limit_failclosed_4926_test.go`, `pkg/api/rest_events_zone0_3338_test.go`, `pkg/api/rest_filter_failclosed_test.go` - C/R/T: forensic fields, bounded event windows, explicit unknown-zone zero, and malformed REST filters are covered; no query broadening or unbounded event read found.
- `pkg/api/show_text.go`, `pkg/api/show_appset_nil_5221_test.go`, `pkg/api/show_text_sorted_4712_test.go` - C/P/T: text projections, nil app-set handling, deterministic ordering, and action rendering were checked; no assigned text path changes configured deny to permit.

### Metrics, counters, and statistics

- `pkg/api/metrics.go`, `pkg/api/metrics_descriptors.go` - C/P/R: collection gates, descriptor registration, label dimensions, dataplane-independent host-inbound signals, scheduler/content rejection, zone collision, reject sources, and cold-path histograms were checked; no new duplicate series or admission-semantic inversion found.
- `pkg/api/metrics_counters.go`, `pkg/api/metrics_counter_read_errors_every_path_5045_test.go`, `pkg/api/metrics_descriptor_coverage_test.go` - C/R/T: unavailable reads omit samples and count errors across global/interface/policy/filter paths; descriptor coverage is pinned and no misleading clean zero found.
- `pkg/api/metrics_cold_path_test.go`, `pkg/api/metrics_cpu_current_4707_test.go`, `pkg/api/metrics_det_pool_blocks_4752_test.go`, `pkg/api/metrics_drop_class_4768_test.go`, `pkg/api/metrics_drops_scope_4508_test.go` - C/R/T: histogram slots, current CPU semantics, deterministic-pool blocks, drop classes, and enforcement-scoped wording are covered; no unbounded scrape loop or false total claim found.
- `pkg/api/metrics_flowexport_test.go`, `pkg/api/metrics_frr_degraded_test.go`, `pkg/api/metrics_neighbor_latency_test.go`, `pkg/api/metrics_pbr_test.go`, `pkg/api/metrics_persist_degraded_test.go` - C/R/T: label uniqueness, degraded gauges, latency accounting, PBR build health, and persistence degradation are covered; no unavailable-as-healthy projection found.
- `pkg/api/metrics_host_inbound_accept_4759_test.go`, `pkg/api/metrics_host_inbound_addressless_3698_test.go`, `pkg/api/metrics_host_inbound_ambiguous_3718_test.go`, `pkg/api/metrics_host_inbound_junos_host_4146_test.go`, `pkg/api/metrics_host_inbound_kernel_test.go`, `pkg/api/metrics_lo0_test.go` - P/T: kernel accept/deny, addressless/ambiguous exposure, junos-host deny, and lo0 counters remain visible without a loaded dataplane; no clean-zero masking found.
- `pkg/api/metrics_ipsec_rebind_4899_test.go`, `pkg/api/metrics_nat_det_ipv6_4692_test.go`, `pkg/api/metrics_surface_a_ddns_test.go`, `pkg/api/metrics_wireguard_test.go` - C/T: IPsec rebind, deterministic NAT family, DDNS, and WireGuard series/labels are checked; no stale-success semantic found.
- `pkg/api/metrics_nat.go` - C/R: NAT utilization/capacity calculations are bounded and config-derived; no divide overflow or policy action widening found.
- `pkg/api/metrics_sessions.go`, `pkg/api/metrics_sessions_cache_test.go`, `pkg/api/metrics_sessions_userspace_3929_test.go` - C/R/T: session summaries, cache state, userspace source, nil/error paths, and bounded aggregation were checked; no HA/session count presented as an allow/deny verdict.
- `pkg/api/metrics_status_dedupe_5317_test.go`, `pkg/api/metrics_system.go`, `pkg/api/metrics_test.go`, `pkg/api/metrics_userspace.go` - C/R/T: status deduplication, system collectors, userspace dispatch, nil/degraded gates, and broad collector registration tests were checked; no lock inversion or unbounded label expansion newly identified in assigned behavior.
- `pkg/api/metrics_auth_gate_4162_test.go`, `pkg/api/metrics_host_inbound_accept_4759_test.go`, `pkg/api/metrics_scoped_global_3286_test.go` - P/T: metrics authentication and scoped-global/host-inbound labels are pinned; no unauthenticated metric exposure or scoped-global `*/*` regression found.
- `pkg/api/filter_counters_metrics_test.go`, `pkg/api/stats.go`, `pkg/api/stats_counter_error_test.go` - C/P/T: filter term/action counters and global/zone/interface REST statistics preserve unavailable/error semantics; zone statistics delegation is request-independent and no deny counter becomes a permit signal.

### Interfaces, DHCP, NAT, routing, IPsec

- `pkg/api/interfaces.go`, `pkg/api/iface_name_test.go`, `pkg/api/interface_counter_error_test.go` - C/R/T: logical/kernel naming, unit parsing, sorted inventory, and counter-unavailable rows were checked; malformed names do not alias another interface and read failures do not hide configured rows.
- `pkg/api/dhcp.go`, `pkg/api/dhcp_clear_chunked_4794_test.go` - C/R/T: lease inventory/clear operations and chunked deletion bound work and propagate failures; no partial clear is reported as complete.
- `pkg/api/nat.go`, `pkg/api/nat_counter_error_test.go`, `pkg/api/nat_stats_test.go` - C/P/R/T: source/destination inventories, pool/rule stats, deterministic and NAT64 fields, counter errors, sorting, and nil config were checked; no translation state is silently relabeled successful.
- `pkg/api/routing.go`, `pkg/api/routes_disposition_5410_test.go`, `pkg/api/routes_ipv6_vrf_5439_test.go` - C/P/T: kernel/config route merging, reject/discard disposition, IPv6, and VRF identity are covered; no reject route is rendered as forwarding or cross-VRF route collapse found.
- `pkg/api/bgp_routes_cap_5056_test.go`, `pkg/api/bgp_routes_stream_4708_test.go` - R/T: BGP route result caps and streaming avoid unbounded response buffering; error/partial output behavior is pinned.
- `pkg/api/ipsec.go` - C/R: thin SA status projection delegates to the bounded manager source and handles errors; no policy permit/deny decision is synthesized here.

### Sessions, HA, SSE, and event streaming

- `pkg/api/sessions.go` - C/P/R: local/peer scope, zone/policy enrichment, strict filters, pagination tokens, caps, iterator errors, aggregation, and clear fan-out were reviewed; no malformed filter widens scope and no session policy action is reinterpreted.
- `pkg/api/session_summary_fields_5320_5323_test.go`, `pkg/api/sessions_aggregation_bound_5433_test.go`, `pkg/api/sessions_iterator_error_test.go` - C/R/T: peer completeness, dynamic maximum, aggregation cap, and iterator failures are surfaced; no incomplete result is labeled complete.
- `pkg/api/sessions_ha_scope_3423_test.go`, `pkg/api/sessions_zonepair_peer_3592_test.go` - P/T: HA node scope and peer zone-pair attribution are pinned; no cross-node double count or zone-pair identity loss found.
- `pkg/api/sessions_pagination_bound_5318_test.go`, `pkg/api/sessions_pagination_test.go` - R/T: admission cap, cursor/offset behavior, stable ordering, and malformed tokens are covered; no unbounded walk or page-scope widening found.
- `pkg/api/sessions_parity_test.go` - C/P/T: list/summary field parity and policy/zone metadata are covered; no normal configured action drift found in session projection.
- `pkg/api/sse.go`, `pkg/api/sse_filter_failclosed_3383_test.go`, `pkg/api/sse_test.go` - C/R/T: category/severity filters, unknown filter rejection, subscriber cleanup, cancellation, and flush behavior were checked; no unknown-filter match-all or leaked subscriber found.


## A8-b2


Every assigned path is ledgered below. Dimensions: `C` correctness/error semantics; `P` policy/zone/vSRX parity; `R` resources/concurrency/bounds; `T` tests/modularity.

- `pkg/api/stats_global_host_inbound_3681_test.go` - C/P/T: exercised degraded and loaded userspace states, clean/failed nftables reads, aggregate and zone/family detail, and userspace versus kernel host-inbound counter separation. The tests preserve unavailable-not-zero semantics and no unintended allow/deny claim was found.
- `pkg/api/stats_global_parity_3426_test.go` - C/P/T: distinct index-derived values pin NAT64 translation, host-inbound allow, and host-inbound deny slots. No counter alias, omission, or permit/deny inversion was found.
- `pkg/api/system.go` - C/R/P: reviewed uptime/memory parsing, bounded ping/traceroute count and deadlines, shared process-wide admission limiter, option separators/VRF normalization, userspace buffer status, legacy map fallback, power actions, audit ordering, and config-lock recovery. Diagnostic output is bounded by child lifetime/concurrency and mutation routes remain behind shared middleware. The uncapped ping payload-size candidate is suppressed as a prior root; no new admission-path defect was found.
- `pkg/api/system_action_audit_4484_test.go` - C/T: reboot/halt journal-before-schedule ordering, nil/store behavior, clear-config-lock, and unknown-action rejection are pinned. The asynchronous systemctl result remains intentionally best-effort and matches gRPC; no new root was retained.
- `pkg/api/system_argv_test.go` - C/R/T: plain, dash-prefixed, source, size, and routing-instance argv shapes preserve the inner and outer `--` separators and apply the VRF prefix exactly once. No shell invocation or option-confusion bypass exists in the tested builder path.
- `pkg/api/system_buffers_test.go` - C/R/T: userspace helper rows, dynamic helper capacities, status errors, missing capacities, and retired-map fallback are covered. Userspace status failure returns 503 instead of stale BPF health; row production is bounded by helper-published bindings and no hot-path work is introduced.
- `pkg/api/tls_test.go` - C/R/T: matching-pair reload, key-first durability, strict stale-pair removal, directory sync, mkdir/write failures, file modes, and in-memory HTTPS continuity are covered. Tests are serial and restore package seams; race validation found no shared-state race. No secret exposure or cert/key mismatch survives.
- `pkg/api/types.go` - C/P/R: reviewed response presence semantics for global/zone/policy/session/status resources, host-inbound kernel and per-zone availability, scoped-global sets, policy identity zero, default sentinel, scheduler state, host-inbound and route-drop advisories, HA peer completeness, and buffer capacities. Policy counter rows lack an availability/presence discriminator, producing `A8-b2-F001`; no other action or scope inversion was retained.
- `pkg/api/vrrp.go` - C/P/R: checked nil config/manager behavior, runtime state lookup, virtual-address slice normalization, status locking, and bounded configured-instance traversal. REST omits generated RETH instances, but the frozen dedup index already contains the same RETH-VRRP status omission root and it is suppressed. The live-priority formatting race is also a prior root; no new VRRP finding remains.
- `pkg/api/write_json_4541_test.go` - C/R/T: marshal-before-header behavior returns valid JSON 500 on unsupported values and preserves exact success bytes/newline. Response construction is bounded by the handler value and no partial 200 is committed on marshal failure.
- `pkg/api/zone_counter_doc_ref_test.go` - C/T: the deferred per-zone userspace counter design and its `section 5A`/`section 5B`/`#3651` anchors are pinned. The test is filesystem-local, bounded, and does not weaken runtime enforcement.
- `pkg/api/zone_counters_hide_test.go` - C/P/R/T: stable-hash IDs above retired dense-map bounds return explicit unavailable counters rather than 500 or false Prometheus errors; no dead per-zone metric is emitted. Global, policy, filter, and host-inbound paths are neutralized or independently tested, so the negative result is substantive rather than hidden by unrelated read failures.
- `pkg/api/zones_policies_counter_error_test.go` - C/P/T: genuine policy/filter counter and filter-config read failures fail REST or omit Prometheus samples while incrementing the error signal; the retired per-zone path stays hidden. Loaded-dataplane read errors are correctly covered, but the tests do not exercise the unloaded-dataplane eligible-counter state in `A8-b2-F001`.


## A8-b3


Every assigned path is listed below. `C` means correctness/error handling, `P` policy/zone/runtime parity, `R` resource/concurrency/bounds, and `T` test coverage. A negative result means the reviewed path yielded no retained new root after caller tracing and deduplication.

### Core server, runtime, authentication, and configuration

- `pkg/grpcapi/apply_result.go` - C/P: apply-result retrieval is a thin loaded-runtime projection; no stale fallback or fabricated identity found.
- `pkg/grpcapi/exec_timeout.go` - R: command context, process-group kill, wait-delay, diagnostic timeout, and tail-line clamps are bounded; no surviving child or unbounded requested line count found.
- `pkg/grpcapi/exec_timeout_test.go` - R/T: stdout/stderr semantics, hung-child kill, inherited-pipe drain, ping/traceroute budgets, and tail cap are pinned.
- `pkg/grpcapi/fabric_auth.go` - C/R: HMAC window verification, downgrade arming, metadata extraction, and per-RPC credentials were traced; no token bypass or unbounded auth state found.
- `pkg/grpcapi/runtime.go`, `pkg/grpcapi/runtime_canary_test.go` - C/T: runtime capability interfaces and compile-time canaries cover counter/session/control methods without hidden permissive fallback.
- `pkg/grpcapi/server.go` - C/R: loopback clamp, receive cap, bounded graceful stop, listener retry/backoff, auth-before-allowlist ordering, config-lock cleanup, and fail-closed fabric methods were checked; no network exposure or retry spin found.
- `pkg/grpcapi/server_grpc_loopback_clamp_5035_test.go` - C/T: wildcard/non-loopback binds clamp and listener shutdown is covered.
- `pkg/grpcapi/server_recvsize_hb164_test.go` - R/T: oversized inbound Load is rejected at the gRPC transport cap.
- `pkg/grpcapi/server_fabric_auth_4107_test.go` - C/T: valid/invalid/tokenless/rollout/heartbeat-armed unary and stream cases plus credential generation are covered.
- `pkg/grpcapi/server_fabric_allowlist_4122_test.go` - C/T: proxied read/monitor methods, nested failover grammar, destructive methods, unknown methods, and loopback separation are covered.
- `pkg/grpcapi/server_fabric_listener_5047_test.go` - R/T: transient/persistent failures, backoff cap, cancellation, and expected server-stop behavior are covered.
- `pkg/grpcapi/config_lock_holder_5059_test.go` - C/R/T: holder identity and concurrent clients are covered; race run passed.
- `pkg/grpcapi/configstore_helper_test.go` - T: isolated store helper only; no production behavior or shared-state leakage.
- `pkg/grpcapi/server_config.go` - C/P: configure ownership, set/delete/load/commit/check/confirmed/rollback, warnings, redaction, and selector checks were traced; strict commits retain terminal-action validation and no mutation reports false success.
- `pkg/grpcapi/server_config_activate_test.go` - C/T: activate/deactivate token routing, tabs, load-set, and bare-verb errors are covered.
- `pkg/grpcapi/server_config_redaction_test.go` - C/T: raw AST and active-config displays redact secrets.
- `pkg/grpcapi/server_config_test.go` - C/P/T: retired dataplane rejection and multi-error strict compile output are covered.
- `pkg/grpcapi/server_rollback_negative_n_4589_test.go`, `pkg/grpcapi/server_show_compare_strict_3443_test.go`, `pkg/grpcapi/server_show_rollback_zero_n_4556_test.go` - C/T: rollback/compare selectors reject negative or non-positive values according to each endpoint contract.
- `pkg/grpcapi/apply_result.go` and `pkg/grpcapi/runtime.go` have no independent allocation, lock, publication, or policy decision beyond their delegated runtime contracts.

### Policy simulator, selectors, completion, counters, and cluster projection

- `pkg/grpcapi/server_cluster.go` - C/P/R: MatchPolicies validates zones/IPs/ports/protocol/ICMP and delegates tier/default/host-inbound/content-rejection/scheduler/route-drop decisions to `policymatch`; completion is config-bounded. Existing nil-map completion root is deduplicated; no new simulator admission root found.
- `pkg/grpcapi/server_cluster_test.go` - P/T: malformed/empty/valid addresses and malformed/valid ports cover wildcard-vs-invalid behavior for structured and text policy tests.
- `pkg/grpcapi/server_matchpolicies_action_3375_test.go` - P/T: host-inbound/default/no-config action fields are nonblank and typed default use is covered.
- `pkg/grpcapi/server_matchpolicies_desc_sched_3685_test.go` - P/T: description, scheduler, global ID, and scope projection are covered.
- `pkg/grpcapi/server_matchpolicies_exclusion_3668_test.go` - P/T: stable rule ID and address-exclusion semantics are covered.
- `pkg/grpcapi/server_matchpolicies_hostinbound_3627_test.go` - P/T: host-inbound token/status and off-host omission are covered.
- `pkg/grpcapi/server_matchpolicies_queried_zones_3627_test.go` - P/T: queried zone pair survives match/default/host paths.
- `pkg/grpcapi/server_matchpolicies_routedrop_4413_test.go` - P/T: broadcast route-drop-before-policy advisory is covered.
- `pkg/grpcapi/server_matchpolicies_scheduler_3414_test.go` - P/T: unavailable scheduler state fails closed instead of certifying a scheduled permit.
- `pkg/grpcapi/server_matchpolicies_scope_3331_test.go` - P/T: wildcard/global scope and runtime policy ID are covered.
- `pkg/grpcapi/server_missing_zone_3355_test.go` - C/T: missing required zones reject rather than defaulting.
- `pkg/grpcapi/server_policy_id_zero_3623_test.go` - C/T: explicit presence preserves matched policy ID zero in inventory and simulator output.
- `pkg/grpcapi/server_proto_validation_test.go` - C/T: malformed structured and text protocol selectors reject instead of widening to any.
- `pkg/grpcapi/server_input_validation_test.go` - C/R/T: completion positions and NAT pool int32 saturation are covered.
- `pkg/grpcapi/complete_utf8_pos_4970_test.go` - C/T: mid-rune completion offsets reject.
- `pkg/grpcapi/completion_test.go`, `pkg/grpcapi/completion_typed_leaf_test.go` - C/T: config/operational prefix resolution and typed leaf examples are covered; they do not add a new nil-tolerant map-value test.
- `pkg/grpcapi/server_cluster_monitor_status_4480_test.go` - C/P/T: local live/fallback and peer monitor status are not fabricated up.
- `pkg/grpcapi/server_cluster.go` `ClearCounters` propagates unavailable/clear errors; no clean-zero success on a failed clear.

### Sessions, NAT, helpers, DHCP, and routing

- `pkg/grpcapi/server_sessions.go` - C/P/R: request validation, page-size cap, cursor codecs, iterator errors, reverse-counter enrichment, zone/policy/interface identity, peer completeness, zone-pair aggregation, bounded filtered clearing, cancellation, companion deletion, and bounded error summaries were traced. No filter widening, O(matches) retained slice, or hidden peer failure found.
- `pkg/grpcapi/pagination_test.go` - C/T: v4/v6 token round trips, invalid token, reverse suppression, and basic zone/protocol predicates are covered.
- `pkg/grpcapi/server_sessions_test.go` - C/T: v4/v6 session output preserves simultaneous SNAT and DNAT legs.
- `pkg/grpcapi/clear_sessions_bounded_5454_test.go` - R/T: bounded chunks, cancellation, benign forward disappearance, and capped failure strings are covered.
- `pkg/grpcapi/clear_sessions_errors_test.go` - C/T: iterator/forward/reverse/DNAT failures and benign not-found cases are distinguished.
- `pkg/grpcapi/clear_sessions_peer_nodeid_3423_test.go` - C/T: partial peer clear names the remaining peer node.
- `pkg/grpcapi/clear_sessions_reversekey_test.go` - C/P/T: translated reverse keys, non-NAT reverse keys, and absent companions are covered.
- `pkg/grpcapi/server_helpers.go` - C/P/R: interface aliases, runtime providers, NAT-session counting, app display, protocol names, and neighbor summaries were checked; iterations are table-bounded and no action verdict is synthesized.
- `pkg/grpcapi/server_nat.go` - C/P/R: NAT source/destination/pool/rule inventories, rule-set session attribution, counter errors, ID snapshots, capacity saturation, and VRRP output were checked; no healthy-zero counter failure or cross-rule-set count leakage found.
- `pkg/grpcapi/server_nat_test.go` - C/R/T: interface-mode attribution, one apply-result read, and session-store provider use are covered.
- `pkg/grpcapi/nat_counter_error_test.go` - C/T: pool and rule counter failures return errors rather than zero.
- `pkg/grpcapi/server_show_nat.go`, `pkg/grpcapi/server_show_nat_shared_test.go`, `pkg/grpcapi/server_show_nat_test.go` - C/P/T: shared NAT renderers and IPv6 persistent bindings are used without panic or policy reinterpretation.
- `pkg/grpcapi/server_dhcp.go` - C/R: address/prefix lease grouping and client identifier clear are manager-bounded; no PD-only loss or unbounded request loop found.
- `pkg/grpcapi/dhcp_leases_pd_only_5382_test.go` - C/T: PD-only, attached PD, and grouped multi-PD leases are covered.
- `pkg/grpcapi/server_routing.go` - C/P/R: partial family route dumps, ECMP rows, fixed FRR queries, BGP neighbor IP validation, and protocol status errors were checked; no reject/discard policy action is relabeled.
- `pkg/grpcapi/server_bgp_status_ip_guard_4588_test.go` - C/T: injected neighbor IPs reject while all-neighbor selector remains valid.
- `pkg/grpcapi/server_show_routes_text.go`, `pkg/grpcapi/server_show_routes_perfamily_5125_test.go` - C/P/T: route text selectors reject malformed grammar/duplicates, and per-family partial output remains visible with warning.

### Diagnostics, monitor streams, and system actions

- `pkg/grpcapi/server_diag.go` - C/R: peer dial uses fixed fabric candidates and bounded probes; no recursive unbounded proxy path found.
- `pkg/grpcapi/server_diag_ping.go` - C/R: argument validation, `--` separation, VRF argv, concurrency admission, stream cancellation, scanner bounds, and process cleanup were traced.
- `pkg/grpcapi/server_diag_argv_test.go` - C/T: ping/traceroute and VRF argument separators are covered.
- `pkg/grpcapi/server_diag_stream_test.go` - R/T: line streaming, send-error kill, timeout clamp, and burst-child cleanup are covered.
- `pkg/grpcapi/server_diag_scanner_leak_5060_test.go` - R/T: overlong scanner input and field-length rejection do not leak a child.
- `pkg/grpcapi/diag_concurrency_5057_test.go` - R/T: shared ping/traceroute concurrency admission is covered; targeted race run passed.
- `pkg/grpcapi/server_diag_monitor.go` - C/P/R: packet-drop node/count/port/protocol/zone/interface validation, bounded subscription, stream cancellation, interface aliases, monitor snapshots, and peer recursion guard were checked; no accepted-never-matches selector found.
- `pkg/grpcapi/server_diag_monitor_test.go` - C/T: dataplane interface counters project without reordering fields.
- `pkg/grpcapi/server_packet_drop_validation_3382_test.go` - C/P/T: invalid inputs, valid selectors, numeric protocol matching, and interface aliases are covered.
- `pkg/grpcapi/server_diag_system_action.go` - C/R: local/proxied actions, audit logging, node/range checks, and fabric nested gate were traced; destructive actions remain off fabric.
- `pkg/grpcapi/server_diag_issu_5039_test.go` - C/T: no-cluster, drain gate, and wire format are covered.
- `pkg/grpcapi/server_diag_zeroize.go` - C/R: bounded directory sweeps, ownership resolution, artifact cleanup, account/key removal, and accumulated failure handling were checked; no policy path or new traversal root found.

### Structured/text show surfaces, policy inventory, and counters

- `pkg/grpcapi/server_show.go` - C/P/R: topic dispatch, strict parameterized selectors, bounded log tail, fixed journal query, and unknown-topic errors were checked; fabric-reachable topics do not add an unbounded session ranking.
- `pkg/grpcapi/server_show_golden_test.go` - T: broad stable text output is covered, but malformed typed policy actions are absent, enabling `A8-b3-F001`.
- `pkg/grpcapi/server_show_policies_text.go` - P/C: tier/global/default counter identities, scheduler state, exclusions, log modes, scoped globals, zone-local names, bulk reads, and warnings were traced. Unknown typed actions default to permit in four render loops: `A8-b3-F001`.
- `pkg/grpcapi/policies_bulk_reader_test.go` - R/T: structured, hit-count, and detail surfaces use one bulk counter snapshot.
- `pkg/grpcapi/server_show_policies_addr_inventory_3336_test.go` - P/T: exclusions and separate log modes are covered.
- `pkg/grpcapi/server_show_policies_hitcount_gate_test.go` - P/T: policy-stats gating is covered.
- `pkg/grpcapi/server_show_policies_hitcount_globals_test.go` - P/T: global rows and counters are covered, but only valid enum actions.
- `pkg/grpcapi/server_show_policies_scheduler_3062_test.go` - P/T: inactive/active/unavailable scheduler labels are covered.
- `pkg/grpcapi/server_show_policies_text_exclusion_3667_test.go` - P/T: detail exclusion, log, and runtime index fidelity are covered.
- `pkg/grpcapi/server_show_policies_text_scoped_global_3357_test.go` - P/T: filtered hit/detail views retain applicable scoped globals.
- `pkg/grpcapi/server_show_policies_thencount_3074_test.go` - P/T: per-rule count overrides the system-wide stats knob.
- `pkg/grpcapi/server_show_policies_zone_local_3358_test.go` - P/T: authored zone-local address names are restored.
- `pkg/grpcapi/server_show_firewall.go` - C/P/R: strict test-policy grammar, shared matcher, content/host/default/global output, filter expansion counters, userspace policer status, and effective snapshot renderers were traced; malformed packet selectors do not widen.
- `pkg/grpcapi/server_show_firewall_test.go` - C/P/T: family selection, userspace counters, policer status, omission, and SYN-cookie rows are covered.
- `pkg/grpcapi/server_show_firewall_effective_4967_test.go` - P/T: compiled effective snapshot and not-found behavior are covered.
- `pkg/grpcapi/flow_cluster_counter_error_test.go` - C/T: flow and fabric text paths warn on counter failure.
- `pkg/grpcapi/global_stats_counter_error_test.go`, `pkg/grpcapi/global_stats_screen_keys_3343_test.go` - C/P/T: early/late global failures error and screen reason keys use the shared catalog.
- `pkg/grpcapi/interface_counter_error_test.go`, `pkg/grpcapi/iface_name_test.go` - C/T: interface read failures are marked unavailable and reth names resolve to kernel identity.
- `pkg/grpcapi/server_show_status.go` - C/R: status/session counts, global counter error aggregation, screen details, and proc parsing were checked; no failed counter is presented as healthy zero.
- `pkg/grpcapi/server_show_interfaces.go`, `pkg/grpcapi/server_show_interfaces_text.go` - C/P/R: logical/kernel/reth/unit/VLAN identity, zone attribution, live state, counters, queue/CoS, and stable ordering were checked; no zone identity collapse or request-controlled unbounded loop found.
- `pkg/grpcapi/server_show_interfaces_reth_4328_test.go` - C/T: RPC/text reth, member, non-reth, detail, and extensive paths are covered.
- `pkg/grpcapi/server_show_cos_gap7_test.go` - C/T: forwarding class, scheduler map, classifier, queue, name/family filters are covered.
- `pkg/grpcapi/server_show_flow.go` - C/P/R: global counter warnings, bounded top-K heap, iterator errors, zone/app enrichment, and traceoptions were checked; no full-table retention remains.
- `pkg/grpcapi/server_show_forwarding.go`, `pkg/grpcapi/server_show_forwarding_adapter_test.go` - C/R/T: local/peer forwarding, map/status adapters, recursion metadata, and timeout behavior were checked.
- `pkg/grpcapi/server_show_chassis.go`, `pkg/grpcapi/server_show_cluster_text.go`, `pkg/grpcapi/server_show_chassis_forwarding_test.go` - C/R/T: chassis/cluster/fabric/status and peer no-dial-back behavior were checked; counter errors remain warnings.
- `pkg/grpcapi/server_show_device_map.go` - C/R: configured and candidate interface mapping is finite and display-only; no forwarding identity mutation.
- `pkg/grpcapi/server_show_dhcp_lldp_snmp.go` - C/R: SNMP/DDNS/DHCP/LLDP views use bounded manager/config snapshots and redact/avoid secrets; no policy verdict synthesis.
- `pkg/grpcapi/server_show_dynamic_address_redact_5521_test.go` - C/T: feed URL credentials are redacted.
- `pkg/grpcapi/server_show_events.go` - C/P/R: event limit cap, explicit zone-zero presence, stored zone names, and forensic fields were checked; no filter widening or unbounded result.
- `pkg/grpcapi/server_show_events_forensic_3337_test.go`, `pkg/grpcapi/server_show_events_historical_zone_3335_test.go`, `pkg/grpcapi/server_show_events_zone0_3338_test.go`, `pkg/grpcapi/server_show_events_zone_3334_test.go` - C/P/T: forensic fields, historical/current fallback, selectable zone zero, out-of-range rejection, and no-filter sentinel are covered.
- `pkg/grpcapi/server_show_security_text.go` - C/P/R: strict event filters, schedulers/apps/screens, screen counters/errors, feeds/address books, IKE/IPsec/WireGuard/RPM, and nil app-set handling were checked; no malformed filter broadening found.
- `pkg/grpcapi/server_show_appid.go`, `pkg/grpcapi/server_show_appid_test.go` - C/T: shared AppID status renderer delegation is pinned.
- `pkg/grpcapi/server_show_appset_nil_5221_test.go` - C/T: nil application-set display is omitted without panic; completion sibling is a prior dedup root.
- `pkg/grpcapi/server_screen_inventory_3327_test.go`, `pkg/grpcapi/server_show_screen_inventory_text_3327_test.go` - P/T: omitted screen checks and thresholds appear in structured and text views.
- `pkg/grpcapi/server_security_nil_3476_test.go` - C/T: nil policy/set/screen/zone slots do not panic assigned inventory/show paths.
- `pkg/grpcapi/server_show_security_log_zone_3547_test.go` - C/P/T: named and zone-zero remote log filters isolate the requested events.
- `pkg/grpcapi/server_show_security_wireguard_test.go` - C/T: summary/detail/empty/public-key topics are covered.
- `pkg/grpcapi/server_show_rpm_test.go` - C/T: absent and effective RPM config rendering is covered.


## A8-b4


1. `pkg/grpcapi/server_show_status_3929_test.go` - Reviewed userspace session-count source and no-dataplane fallback; no stale-map, false healthy, or nil-path defect found.
2. `pkg/grpcapi/server_show_system.go` - Reviewed system text renderers, external-command cancellation, buffer status fallback, allocation/sort bounds, secret presentation, and unavailable-state handling; no additional defect found.
3. `pkg/grpcapi/server_show_system_buffers_test.go` - Reviewed userspace status/detail and session-total assertions; no missing error or parity case found in the exercised contract.
4. `pkg/grpcapi/server_show_test_routing_dupselector_4921_test.go` - Reviewed duplicate-key fail-closed coverage and distinct-selector refutation; no defect found.
5. `pkg/grpcapi/server_show_test_routing_unknownkey_4589_test.go` - Reviewed unknown/malformed routing selector rejection and valid-selector control; no defect found.
6. `pkg/grpcapi/server_show_test_zone_selector_4814_test.go` - Reviewed malformed/unknown zone selectors; found missing duplicate-interface coverage corresponding to the finding below.
7. `pkg/grpcapi/server_show_testpolicy_srcport_test.go` - Reviewed source-port parsing, application resolution, and invalid range rejection; no unintended match widening found.
8. `pkg/grpcapi/server_show_zones.go` - Traced zone, host-inbound, policy tier/default, scheduler, scoped-global, stable ID, counter, and screen inventory; duplicate test-zone validation defect is in its text sibling, with no structured inventory defect found here.
9. `pkg/grpcapi/server_show_zones_default_policy_3363_test.go` - Reviewed synthetic default-policy row/action/ID presence; no omission found.
10. `pkg/grpcapi/server_show_zones_default_policy_log_3670_test.go` - Reviewed default init/close log parity; no false logged/unlogged state found.
11. `pkg/grpcapi/server_show_zones_explicit_any_3680_test.go` - Reviewed explicit-any global applicability in zone detail; no unintended suppression found.
12. `pkg/grpcapi/server_show_zones_hostinbound_3328_test.go` - Reviewed enforcing/default-deny posture, split service/protocol fields, and interface overrides; no fail-open representation found.
13. `pkg/grpcapi/server_show_zones_hostinbound_display_3654_test.go` - Reviewed zone and effective per-interface host-inbound text; no union/default-deny display drift found.
14. `pkg/grpcapi/server_show_zones_lifeline_3682_test.go` - Reviewed management/cluster lifeline exemption disclosure; no hidden exemption found.
15. `pkg/grpcapi/server_show_zones_metadata_3684_test.go` - Reviewed policy IDs, scheduler state, log/count/exclusion, and default metadata; no parity defect found.
16. `pkg/grpcapi/server_show_zones_policy_tiers_3658_test.go` - Reviewed zone-pair, applicable global, and terminal default ordering; no tier omission found.
17. `pkg/grpcapi/server_show_zones_scheduler_inventory_3624_test.go` - Reviewed active, inactive, and unavailable scheduler-provider states; no runtime-inventory inversion found.
18. `pkg/grpcapi/server_show_zones_scoped_global_3286_test.go` - Reviewed singular/plural scope and text filtering for scoped globals; no scope widening found.
19. `pkg/grpcapi/server_show_zones_test.go` - Reviewed local/global scheduled counters and policy-stats/count gating; no counter-handle or gating defect found.
20. `pkg/grpcapi/server_show_zones_text.go` - Reviewed zone counters, nil tolerant shapes, host-inbound, screens, policy tier SSOT, and test-zone parser; duplicate known selector silently last-wins as detailed below.
21. `pkg/grpcapi/server_shutdown_monitor_4910_test.go` - Reviewed stuck stream and idle server shutdown bounds; no goroutine/resource-lifetime defect found in the covered paths.
22. `pkg/grpcapi/server_testpolicy_dup_3709_test.go` - Reviewed duplicate policy selector rejection; no last-wins simulator ambiguity found.
23. `pkg/grpcapi/server_testpolicy_strictness_3696_test.go` - Reviewed malformed, unknown, empty, and valid policy selector grammar; no widening found.
24. `pkg/grpcapi/server_zone_nil_3493_test.go` - Reviewed nil zone handling in inventory and session filters; no panic or wildcard admission found.
25. `pkg/grpcapi/session_app_srcport_3428_test.go` - Reviewed source-port threading into application resolution with positive/negative controls; no app mislabel found.
26. `pkg/grpcapi/session_egress_drift_4650_test.go` - Reviewed displayed egress interface parity across stored/resolved forms; no stale-egress representation found.
27. `pkg/grpcapi/session_filter_3439_test.go` - Reviewed invalid protocol and negative cursor/legacy offsets; no silent filter broadening found.
28. `pkg/grpcapi/session_filter_test.go` - Reviewed NAT-pool, prefix, port, protocol, and validation behavior; no unintended inclusion/exclusion found.
29. `pkg/grpcapi/session_summary_fields_5320_5323_test.go` - Reviewed helper capacity and explicit peer OK/unreachable/not-applicable states; no healthy-zero ambiguity found.
30. `pkg/grpcapi/sessions_iterator_error_test.go` - Reviewed legacy list and summary iterator failures; both fail with Internal rather than returning partial success.
31. `pkg/grpcapi/sessions_top_5319_test.go` - Reviewed bounded top-K equivalence, iterator errors, and survivor-only enrichment; no unbounded materialization or ranking defect found.
32. `pkg/grpcapi/system_action_failover_node_4693_test.go` - Reviewed unsupported target-node rejection before proxy; no connection-churn or action widening found.
33. `pkg/grpcapi/system_action_journal_4108_test.go` - Reviewed destructive verb journaling order and zeroize invocation; no missing audited verb found.
34. `pkg/grpcapi/system_action_test.go` - Reviewed peer forwarding loops, target validation, userspace injection decoding, and dynamic-DNS availability; no additional authz/validation defect found.
35. `pkg/grpcapi/test_commands_test.go` - Reviewed simulator/runtime agreement on fixed allow/deny/application cases; no terminal-action divergence found.
36. `pkg/grpcapi/text_filter_flood_counter_error_test.go` - Reviewed filter, zone, and screen counter failure disclosure including partial reads; no clean-zero masking found.
37. `pkg/grpcapi/xpfv1/xpf.pb.go` - Regenerated from `proto/xpf/v1/xpf.proto` with protoc-gen-go v1.36.11 and compared byte-for-byte; descriptors, presence fields, bounds, and messages show no drift.
38. `pkg/grpcapi/xpfv1/xpf_grpc.pb.go` - Regenerated with protoc-gen-go-grpc v1.6.1 and compared byte-for-byte; method names, handlers, stream shapes, interceptor entry points, and service descriptor show no drift.
39. `pkg/grpcapi/zeroize_configdb_4576_test.go` - Reviewed SSOT/master-key/journal wipe, rollback classification, and surfaced failure; no retained tested secret or false success found.
40. `pkg/grpcapi/zeroize_durable_5197_test.go` - Reviewed directory fsync ordering and sync-error propagation; no success-before-durability defect found.
41. `pkg/grpcapi/zeroize_login_4598_test.go` - Reviewed provenance-owned account deletion, bystander preservation, and marker retention on userdel failure; no ownership widening found.
42. `pkg/grpcapi/zeroize_login_failclosed_5496_test.go` - Reviewed unreadable/malformed passwd, bad marker, UID mismatch, and retry rediscovery; no uncertain-ownership deletion found.
43. `pkg/grpcapi/zeroize_login_root_5520_test.go` - Reviewed managed-root key removal/password lock and retry marker retention; no UID-0 deletion or false success found.
44. `pkg/grpcapi/zeroize_rendered_4585_test.go` - Reviewed FRR/swanctl/Kea secret removal and unmanaged FRR preservation; no tested rendered-secret residue found.
45. `pkg/grpcapi/zeroize_rendered_temp_5509_test.go` - Reviewed fsatomic temp sweep and absent-directory handling; no tested temporary secret residue found.
46. `pkg/grpcapi/zeroize_temp_5475_test.go` - Reviewed config-directory fsatomic temp classification/sweep and bystander preservation; no over-delete or tested residue found.
47. `pkg/grpcapi/zeroize_tls_4599_test.go` - Reviewed API TLS key/certificate wipe and bystander preservation; no tested credential residue found.
48. `pkg/grpcapi/zone_flood_counters_hide_test.go` - Reviewed unsupported userspace zone/flood counters as unavailable rather than zero; no misleading counter output found.
49. `pkg/grpcapi/zonepair_summary_3592_test.go` - Reviewed local aggregation, iterator failure, peer fan-out, recursion guard, node ID, and no-peer behavior; no partial-success or fan-out loop found.
50. `pkg/grpcapi/zones_policies_counter_error_test.go` - Reviewed structured zone/policy counter failures; both return Internal rather than healthy zero.


## A9-b1


Disposition key: `OK` means reviewed with no distinct, non-deduplicated defect found; the text names the principal negative checks performed. `F1` is the finding below.

### Event engine

- `pkg/eventengine/engine.go` — OK: traced semantic revisions, strict/lenient attribute failure, queue bound/supersession, stale revalidation, configure-lock retry, commit debt, timer cancellation, and cooldown/window ownership.
- `pkg/eventengine/engine_4423_test.go` — OK: reviewed scalability/bounds regression coverage and no contradictory admission expectation.
- `pkg/eventengine/engine_armed_debt_5063_test.go` — OK: promotion tri-state and cooldown-on-committed-debt coverage are consistent.
- `pkg/eventengine/engine_cooldown_rev_5311_test.go` — OK: revision-aware cooldown ABA coverage is substantive.
- `pkg/eventengine/engine_edge_trigger_3756_test.go` — OK: edge latch re-arm and sustained-level behavior covered.
- `pkg/eventengine/engine_inclusive_until_3756_test.go` — OK: inclusive `until` threshold semantics covered.
- `pkg/eventengine/engine_integration_test.go` — OK: transactional candidate, commit, failure, and remediation integration paths reviewed.
- `pkg/eventengine/engine_stale_revalidate_3750_test.go` — OK: removed/redefined/cooldown stale actions fail closed.
- `pkg/eventengine/engine_supersede_race_5062_test.go` — OK: producer serialization and survivor preservation race covered.
- `pkg/eventengine/engine_test.go` — OK: base matching, actions, lifecycle, and malformed input behavior reviewed.
- `pkg/eventengine/engine_window_test.go` — OK: sliding-window pruning and threshold behavior covered.
- `pkg/eventengine/engine_within_failclosed_3751_test.go` — OK: unusable legacy temporal thresholds do not fire remediation.

### Dynamic feeds

- `pkg/feeds/feeds.go` — OK: traced deterministic duplicate handling, snapshot handoff, cancellation, HTTPS warning, body/line/count/sample bounds, canonical hash, retain-last-good, and callback publication. A canceled old fetch can only mutate its detached state and cause a redundant callback, not overwrite the live map.
- `pkg/feeds/feeds_bindings_test.go` — OK: binding union, empty/unknown distinction, and copy isolation covered.
- `pkg/feeds/feeds_dup_name_4913_test.go` — OK: duplicate effective names have deterministic single ownership.
- `pkg/feeds/feeds_samplecap_4922_test.go` — OK: hostile invalid-line samples remain byte/count bounded.
- `pkg/feeds/feeds_sizecap_3934_test.go` — OK: body and prefix caps reject whole snapshots and retain last-good.
- `pkg/feeds/feeds_snapshot_handoff_5282_test.go` — OK: reconfigure keeps the enforced snapshot without an empty interval.
- `pkg/feeds/feeds_test.go` — OK: fetch status, canonicalization, staleness, hold interval, and update callbacks reviewed.

### Flow export

- `pkg/flowexport/addr_format_test.go` — OK: IPv4/IPv6 address encoding parity covered.
- `pkg/flowexport/collector_health_test.go` — OK: health edges and counters reviewed.
- `pkg/flowexport/collector_stall_4423_test.go` — OK: write deadlines and unhealthy backoff bound collector stalls.
- `pkg/flowexport/cos_fields_test.go` — OK: ToS/TCP flags/interface fields map to declared wire IEs.
- `pkg/flowexport/dropped_fields_test.go` — OK: intentional template omissions are asserted.
- `pkg/flowexport/exporter_id_3740_test.go` — OK: stable per-group observation identity and isolation covered.
- `pkg/flowexport/exporter_test.go` — OK: exporter construction, batching, templates, counters, and close paths reviewed.
- `pkg/flowexport/exporterid.go` — OK: SHA-256 identity input is length-delimited/stable and used as an identifier, not an authenticator.
- `pkg/flowexport/flowbatch_bounded_test.go` — OK: per-family cap, drops, depth, and high-water behavior covered.
- `pkg/flowexport/flowdir_test.go` — OK: input/output zone selection and tie precedence covered.
- `pkg/flowexport/flowstart_test.go` — OK: creation timestamp and bounded fallback duration behavior reviewed.
- `pkg/flowexport/handoff_lease_4963_test.go` — OK: retirement waits for admitted writers and rejects/counts late records.
- `pkg/flowexport/ingress_interface_test.go` — OK: SNMP ifIndex attribution is numeric and family-consistent.
- `pkg/flowexport/instance_isolation_test.go` — OK: family and instance collector isolation covered.
- `pkg/flowexport/ipfix.go` — OK: checked template/data lengths, endian writes, sequence accounting, biflow/NAT/zone direction fields, chunk bounds, mutex scope, collector lifetime, and retirement.
- `pkg/flowexport/ipfix_biflow_test.go` — OK: reverse counters and enterprise IEs covered.
- `pkg/flowexport/ipfix_sampler_test.go` — OK: flow-level sampling options and sequence effects covered.
- `pkg/flowexport/ipfix_seqnum_test.go` — OK: template/options/data sequence semantics covered.
- `pkg/flowexport/manager.go` — OK: traced strict config resolution, collector grouping/dedup, stable ordering, zone-to-unit lookup, family service, shared sample counter, and direction attribution.
- `pkg/flowexport/maxdepth_race_5048_test.go` — OK: CAS high-water mark cannot regress under concurrent adders.
- `pkg/flowexport/multigroup_wire_4422_test.go` — OK: template-group wire isolation covered.
- `pkg/flowexport/netflow.go` — OK: checked record widths/padding, endian writes, sequence/header fields, NAT/biflow/zone direction, chunk bounds, and close lifetime.
- `pkg/flowexport/netflow_multirecord_4896_test.go` — OK: multi-record offsets and padding covered.
- `pkg/flowexport/per_collector_source_3745_test.go` — OK: source bind is per collector and errors clean up prior sockets.
- `pkg/flowexport/postnat_test.go` — OK: translated and untranslated tuple fallback covered.
- `pkg/flowexport/protocol_num_test.go` — OK: raw protocol number survives instead of name re-resolution.
- `pkg/flowexport/routemask.go` — OK: cache/inflight work is bounded, IP keys are copied, lock scope is finite, and unresolved masks remain observable.
- `pkg/flowexport/routemask_vrf_test.go` — OK: route mask lookup uses ingress/outgoing interface scope.
- `pkg/flowexport/srcmask_dstmask_test.go` — OK: source/destination prefix lengths map to matching IEs.
- `pkg/flowexport/template_group_test.go` — OK: deterministic group resolution and template identity covered.
- `pkg/flowexport/transport.go` — OK: checked partial construction cleanup, UDP deadline/backoff, synchronized health state, bounded batch admission, retirement lease, and connection close.
- `pkg/flowexport/transport_test.go` — OK: collector dial/source/cleanup and transport behavior covered.
- `pkg/flowexport/version_binding_test.go` — OK: v9/IPFIX family-version binding cannot cross-export.

### Logging

- `pkg/logging/aggregator.go` — OK: Space-Saving maps/heaps are bounded, mutex protected, reset atomically, and flush logging occurs outside mutation.
- `pkg/logging/aggregator_flush_5313_test.go` — OK: cancellation flush preserves final aggregate visibility.
- `pkg/logging/aggregator_test.go` — OK: cardinality, byte/session ranking, reset, callback, and cancellation behavior reviewed.
- `pkg/logging/binary_test.go` — OK: binary length/endian/field layout, close-action sentinel, policy/zone/interface/session attribution reviewed.
- `pkg/logging/default_policy_sentinel_3057_test.go` — OK: default-policy sentinel resolves truthfully rather than appearing unknown.
- `pkg/logging/event_filter_args.go` — OK: count bounds, explicit zone-presence state, and unknown arguments fail closed.
- `pkg/logging/event_filter_args_test.go` — OK: parser positive/negative and zone-zero cases covered.
- `pkg/logging/event_severity_test.go` — OK: event type/action severity mapping reviewed.
- `pkg/logging/event_time_test.go` — OK: decision timestamp overflow/zero fallback covered.
- `pkg/logging/eventbuf.go` — OK: ring size and subscriber count are bounded; close/send ordering, per-subscriber drop/overrun, negative count, and zone-zero filtering are synchronized.
- `pkg/logging/eventbuf_close_3384_test.go` — OK: unsubscribe-before-close race covered.
- `pkg/logging/eventbuf_drop_visibility_5064_test.go` — OK: drops, sequence gaps, and overrun notification covered.
- `pkg/logging/eventbuf_negative_3342_test.go` — OK: nonpositive ring/query values cannot panic or allocate negatively.
- `pkg/logging/eventbuf_subscriber_cap_4484_test.go` — OK: untrusted subscription cap and recovery covered.
- `pkg/logging/eventbuf_zone0_3338_test.go` — OK: unknown/pre-zone attribution remains filterable.
- `pkg/logging/goid.go` — OK: bounded stack-prefix parsing is diagnostic only; parse failure returns zero.
- `pkg/logging/host_inbound_deny_3610_test.go` — OK: host-inbound reason remains distinct from transit policy deny.
- `pkg/logging/locallog.go` — OK for production event-mode use: hardened regular-file open, serialized writes/close, rotation failure counters, and finite retention reviewed. The dormant exported emergency-sentinel mismatch has no production configuration caller and was not elevated.
- `pkg/logging/locallog_format_3409_test.go` — OK: standard/structured/sd-syslog/binary dispatch covered.
- `pkg/logging/locallog_test.go` — OK: file lifecycle, rotation, category, ordinary severity, and error paths reviewed; no emergency-sentinel test exists.
- `pkg/logging/per_policy_log_test.go` — OK: policy log bit suppresses human sinks while preserving flow-export callbacks.
- `pkg/logging/protocol_num_builder_3382_test.go` — OK: raw protocol number is authoritative.
- `pkg/logging/protoname_test.go` — OK: named and numeric protocol rendering covered.
- `pkg/logging/ringbuf.go` — OK: traced 144/152/160-byte guards, endian decode, policy-close slot, host-inbound reason, zone/interface/app/session attribution, callbacks before log suppression, sink swaps, and binary encoding bounds.
- `pkg/logging/rtflow_sessionid_4915_test.go` — OK: stable create/close session identity and legacy fallback covered.
- `pkg/logging/session_close_binary_slog_4914_test.go` — OK: close action is not falsely rendered as deny.
- `pkg/logging/session_close_format_test.go` — OK: close reason/counters/NAT and omission rules covered.
- `pkg/logging/session_close_slog_policyid_4796_test.go` — OK: trailing admitting-policy ID reaches slog.
- `pkg/logging/session_create_format_test.go` — OK: create formatting and attribution covered.
- `pkg/logging/slog_handler.go` — OK: reentrancy suppression and client-set snapshots are mutex protected; clients own close/send serialization.
- `pkg/logging/syslog.go` — F1: unknown transport tokens silently select UDP. Other checks: TLS uses verified system roots/SNI inference, stream writes have deadlines/framing teardown, reconnect is bounded, close is terminal, and counters are atomic.
- `pkg/logging/syslog_close_resurrection_4806_test.go` — OK: send after close cannot reconnect.
- `pkg/logging/syslog_lazy_connect_3351_test.go` — OK: valid TCP/TLS down-at-apply clients recover with cooldown.
- `pkg/logging/syslog_partial_frame_3874_test.go` — OK: partial stream frames force teardown before later writes.
- `pkg/logging/syslog_reentrancy_test.go` — OK: warning fanout cannot recursively deadlock the same client.
- `pkg/logging/syslog_replace_close_3579_test.go` — OK: replaced clients close without holding the reader set lock.
- `pkg/logging/syslog_resilience_test.go` — OK: timeout, reconnect, cooldown, drop counters, and recovery paths covered.
- `pkg/logging/syslog_test.go` — OK for valid transports: UDP/TCP/TLS, framing, filtering, and close behavior covered; no unknown-transport negative test exists.
- `pkg/logging/trace.go` — OK: filename traversal/symlink/nonregular guards, mutex lifetime, bounded rotation, write-loss counters, flag/filter fail-closed behavior, and address parsing reviewed.
- `pkg/logging/trace_filter_3422_test.go` — OK: invalid filters do not broaden matching.
- `pkg/logging/trace_size_3424_test.go` — OK: file size/count constraints and rotation behavior covered.
- `pkg/logging/trace_test.go` — OK: construction, filtering, formatting, close, rotation, and hardening reviewed.

### RPM

- `pkg/rpm/display.go` — OK: sorted deterministic display and nil-safe scalar formatting reviewed.
- `pkg/rpm/event_buffer_3755_test.go` — OK: pre-callback events are bounded and replayed in order.
- `pkg/rpm/http_scheme_2495_test.go` — OK: HTTP target schemes are restricted to HTTP/HTTPS.
- `pkg/rpm/http_transport_leak_4912_test.go` — OK: per-probe transport disables keepalive, drains/closes body, and closes idle connections.
- `pkg/rpm/icmp.go` — OK: raw socket options, setup-vs-path failure classification, scoped DNS, link-local zones, ID/seq/peer matching, deadline, and close lifetime reviewed.
- `pkg/rpm/icmp_ctx_2647_test.go` — OK: hostname resolution observes probe cancellation.
- `pkg/rpm/icmp_linklocal_2494_test.go` — OK: explicit/derived scope and fail-closed missing-scope behavior covered.
- `pkg/rpm/icmp_test.go` — OK: echo marshal/match, wrong replies, timeout, and setup errors covered.
- `pkg/rpm/pin_hold_test.go` — OK: failed/missing pin installation holds state instead of probing an unintended route.
- `pkg/rpm/probe_dialer_2492_test.go` — OK: invalid source address fails setup rather than silently binding any address.
- `pkg/rpm/resolver_setup_5061_test.go` — OK: scoped resolver bind failures retain setup classification.
- `pkg/rpm/rpm.go` — OK: traced stop/wait/apply ordering, result snapshots, threshold state, setup holds, bounded event buffer, callback lock release, source/VRF/mark precedence, HTTP/TCP resource closure, and status transitions.
- `pkg/rpm/scoped_hostname_2493_test.go` — OK: scoped hostnames resolve through the scoped resolver.
- `pkg/rpm/transition_cycle_test.go` — OK: one status transition per probe cycle and threshold carry-over covered.


## A9-b2


| Path | Review result |
|---|---|
| `pkg/snmp/agent.go` | Read completely. Traced listener bind/serve/stop, config snapshots, community/source authorization, v1/v2c dispatch, SET refusal, GET/GETNEXT/GETBULK bounds, IF-MIB values, BER parsing, EngineID/boots persistence, and interface snapshot cost. Negative for unintended admission/denial after suppressing prior fixed roots. Shutdown queue accounting contributes to Finding 2. |
| `pkg/snmp/agent_clients_4289_test.go` | Source-CIDR allow and deny tests cover scoped/unscoped communities; no residual source-policy parity defect found. |
| `pkg/snmp/agent_secret_log_4302_test.go` | Unknown-community and denied-SET log redaction are pinned; no secret-bearing log argument found in the reviewed handlers. |
| `pkg/snmp/agent_set_test.go` | Read-only/read-write, deletion, downgrade, nil config, and update/serve race cases cover the live v2c SET gate; no bypass found. |
| `pkg/snmp/agent_stop_leak_4916_test.go` | Confirms watcher and worker exit/no post-stop delivery, but does not assert accounting of jobs abandoned at shutdown; gap is Finding 2. |
| `pkg/snmp/agent_test.go` | Broad BER, OID, MIB, crypto helper, and IF-MIB tests pass. Counter values are fixture-fed and faithfully encoded; no zone/policy counter bridge exists here. |
| `pkg/snmp/agent_v1_polling_5049_test.go` | v1 GET/GETNEXT, Counter64 exclusion, source allowlist, malformed input, size, and SET behavior are covered; no v1/v2c authorization divergence found. |
| `pkg/snmp/ber_timeticks_4924_test.go` | Canonical high-bit TimeTicks encoding and sysUpTime path are pinned; no wrap/encoding regression found in scope. |
| `pkg/snmp/engineid_4917_test.go` | EngineID length, determinism, and hostname differentiation are covered; superseded uniqueness behavior is additionally covered by the 5283 suite. |
| `pkg/snmp/engineid_5283_test.go` | Clone uniqueness, reboot stability, RFC length, localized-key divergence, persistence format, and permissions are covered; catastrophic identity-source failure is logged and does not silently claim uniqueness. |
| `pkg/snmp/getbulk_order_5065_test.go` | Repetition-major ordering, independent cursors, exhausted columns, and v2c/v3 parity are covered; no ordering false-deny or wrong-value defect found. |
| `pkg/snmp/getbulk_size_test.go` | v2c/v3 response trimming, msgMaxSize floor, tooBig fallback, and single interface snapshot are covered; prior response-amplification root is suppressed as fixed. |
| `pkg/snmp/getresp_size_4918_test.go` | GET/GETNEXT tooBig behavior and logarithmic trim search are covered; no unbounded response found. |
| `pkg/snmp/traps.go` | Read completely. Traced category/version selection, deterministic community, target framing, bounded asynchronous queue, stop checks, delivery logs, and queue resource ownership. Abandoned jobs are not counted, Finding 2. |
| `pkg/snmp/traps_async_2991_test.go` | Nonblocking delivery, queue-full drop counting, and async success are covered; shutdown-abandon accounting is absent. |
| `pkg/snmp/traps_categories_5522_test.go` | Empty/all and explicit link-category semantics are covered at helper and dispatch levels; no category filter bypass found. |
| `pkg/snmp/traps_community_2989_test.go` | Deterministic community selection and emitted packet use are covered; no map-order nondeterminism remains. |
| `pkg/snmp/traps_test.go` | Link up/down packet shape, no-config behavior, target dispatch, and varbind OIDs are covered; no malformed trap construction found. |
| `pkg/snmp/traps_version_3948_test.go` | v1 PDU structure and v1/v2/all dispatch parity are covered; unknown versions conservatively follow the documented v2 default. |
| `pkg/snmp/v3.go` | Read completely. Traced key localization, message/USM parsing, minimum security level, HMAC/timeliness/decrypt order, context gating, PDU dispatch, response bounds, privacy salt, encryption, reports, and auth insertion. Report counters are placeholders, Finding 1. |
| `pkg/snmp/v3_auth_test.go` | Positional auth-parameter location, collision cases, long lengths, malformed packets, zeroing, and MAC insertion are covered; no HMAC field-confusion regression found. |
| `pkg/snmp/v3_context_test.go` | Default context service and non-default empty-view behavior are covered; no default-view disclosure through contextName found. |
| `pkg/snmp/v3_priv_iv_test.go` | AES decrypt IV uses received boots/time and wrong-IV behavior is negative-tested; no local-clock IV regression found. |
| `pkg/snmp/v3_priv_salt_5032_test.go` | Monotonic uniqueness, encrypted-message salt divergence, and concurrent uniqueness are covered; no within-boot IV reuse found. |
| `pkg/snmp/v3_rand_failclosed_test.go` | RNG seed failure and response drop are covered; no privacy-to-plaintext downgrade remains. |
| `pkg/snmp/v3_seclevel_test.go` | noAuthPriv rejection and per-user auth/privacy floors are covered; compiler-produced credentialed users cannot be queried below configured security. |
| `pkg/snmp/v3_set_test.go` | SNMPv3 SET uniformly returns notWritable and does not mutate data; no v2c read-write behavior leaks into v3. |
| `pkg/snmp/v3_timeliness_test.go` | In-window/boundary acceptance, stale/future/wrong-boots denial, discovery, persisted boots, corruption, ceiling, and persist failure are covered. The report OID is exercised, but its counter value is not asserted; Finding 1. |


## A10-b1


Disposition key: `OK` means reviewed with no distinct, non-deduplicated defect found. `F1` is the finding below. “Retired” means the code is not executable in the current forwarding path; any surviving ABI role is stated explicitly.

### Z7 BPF / Userspace ABI Boundary

- `bpf/headers/xpf_common.h` — OK, mixed live ABI/retired residue: checked `MAX_INTERFACES` build threading, `MAX_ZONES`, host-inbound flags, event layout, `pkt_meta`, and `flow_config`. `MAX_INTERFACES` remains live in the Rust shim build; event/conntrack-adjacent layouts remain compatibility contracts. Tail-call policy constants, `pkt_meta` policy state, and host-inbound bit enforcement are retired and do not drive AF_XDP policy decisions.
- `bpf/headers/xpf_conntrack.h` — OK, live on-map ABI only: checked v4/v6 session sizes, zone/policy fields, alignment, and the Go/Rust 128/176-byte assertions. Hash helpers and old eBPF conntrack behavior are retired.
- `bpf/headers/xpf_helpers.h` — OK, retired packet logic: reviewed bounds/checksum/fragment/filter/zone/host-inbound helpers for residue classification. No current program includes this header; live userspace behavior resides in Rust. References from comments/tests do not make these policy evaluators callable.
- `bpf/headers/xpf_maps.h` — OK, mixed ABI catalog/retired maps: checked shared map names, key/value layouts, capacities, zone/policy/NAT declarations, dense-index assumptions, and the userspace shim registrations. The old zone-pair/policy/default-policy evaluator maps are retired; selected session, redirect, binding, heartbeat, and reverse-NAT shapes remain ABI documentation or registration inputs.
- `bpf/headers/xpf_nat.h` — OK, retired implementation: checked packet bounds, checksum updates, v4/v6/NAT64/NPTv6 rewrite helpers, and byte-order conventions. The Rust implementation cites this file for parity, but no live BPF program calls it.
- `bpf/headers/xpf_trace.h` — OK, retired diagnostics: compile-time trace macros only serve deleted eBPF stages and have no live admission/denial effect.

### Remote CLI Command Core

- `cmd/cli/clear.go` — F1: policy hit-count clear accepts trailing operands and still issues the global mutation. Other checks: session-clear selectors reject unknown/missing values; ports are bounded; malformed DHCP selectors cannot collapse to clear-all.
- `cmd/cli/main.go` — OK: traced local-only dispatch, bounded configure exit, commit/rollback handling, terminal load abort, strict `test policy` selector parsing, delimiter rejection, and security-zone topic construction.
- `cmd/cli/monitor.go` — OK: monitor cancellation/raw-mode lifetime is bounded; packet-drop selectors reject unknown/missing/malformed values before opening the stream; count is capped at 8192.
- `cmd/cli/request.go` — OK for Z7: reviewed confirmation gates, failover node arity, userspace parser delegation, IPsec/WireGuard actions, and non-TTY behavior. Several unrelated mutators accept trailing words, but no new root was raised beyond F1’s command-arity class because they are outside zone-policy and did not create a distinct policy ABI failure.
- `cmd/cli/shared.go` — OK: operational/config dispatch, pipe filters, command contexts, rollback int32 bounds, completion position, configure-lock exit, and RPC cancellation reviewed.
- `cmd/cli/show.go` — OK for assigned policy boundary: security routes to the dedicated handler; effective firewall selection reaches compiled-snapshot topics. Loose non-policy show grammars are read-only and were not elevated.
- `cmd/cli/show_dhcp.go` — OK: thin structured renderers; reader errors and empty results remain visible.
- `cmd/cli/show_firewall_effective.go` — OK: family/name extraction is bounded and does not alter enforcement. Unknown/duplicate modifiers are a read-only grammar limitation, not a packet-policy path.
- `cmd/cli/show_flow.go` — OK: strict session selector grammar, numeric zone/port bounds, action exclusivity, pagination/summary dispatch, and policy/session rendering reviewed.
- `cmd/cli/show_interfaces.go` — OK: topic selection is read-only; host-inbound effective semantics are server-side for this surface.
- `cmd/cli/show_nat.go` — OK: structured source/destination pool/rule rendering, zone attribution, counters, and empty response handling reviewed.
- `cmd/cli/show_protocols.go` — OK: protocol topic mapping and detail/name handling are read-only.
- `cmd/cli/show_security.go` — OK after dedup: traced policy tiers/default, scoped-global set filtering, stable IDs, excluded-address metadata, scheduler inactivity, strict typed match requests, ICMP/port/protocol parsing, server verdict rendering, host-inbound warning, event filters, and policy-RPC error propagation. Two real residuals were suppressed as prior roots: loose inventory selector parsing (prior review 175) and raw gRPC physical/unit host-inbound inventory (`#3720` deferred M07/L05).
- `cmd/cli/show_services.go` — OK: read-only topic mapping; no zone-policy decision is synthesized locally.
- `cmd/cli/show_system.go` — OK: rollback selector parsing uses bounded int32 conversion and read-only topics preserve errors.

### Remote CLI Regression Tests

- `cmd/cli/clear_dhcp_duid_4883_test.go` — OK: malformed selectors issue no clear-all RPC; intentional bare clear remains covered.
- `cmd/cli/commit_rollback_4868_test.go` — OK: rollback/confirmed arity and int32 overflow coverage reviewed.
- `cmd/cli/completion_pos_4970_test.go` — OK: cursor positions are rune-aware and bounded.
- `cmd/cli/grpc_maxrecv_5321_test.go` — OK: client receive cap wiring is pinned.
- `cmd/cli/load_terminal_abort_4883_test.go` — OK: terminal abort/error never submits partial configuration.
- `cmd/cli/local_only_verb_4909_test.go` — OK: offline/local verbs do not require daemon reachability.
- `cmd/cli/main_test.go` — OK: baseline dispatch/topic behavior reviewed.
- `cmd/cli/monitor_keyreader_4694_test.go` — OK: key-reader cancellation and blocked-reader lifetime are covered.
- `cmd/cli/monitor_packetdrop_5051_test.go` — OK: malformed/unknown filters open no stream; valid bounded requests are preserved.
- `cmd/cli/nontty_test.go` — OK: fake-client call recording and destructive non-TTY confirmation guards are substantive.
- `cmd/cli/pipe_filter_case_4968_test.go` — OK: case-insensitive include/exclude behavior reviewed.
- `cmd/cli/policymatch_dup_3709_test.go` — OK: duplicate typed selectors and delimiter-fragile zone names fail before RPC/topic publication.
- `cmd/cli/query_strictness_3696_test.go` — OK: unknown, missing, and empty policy-simulation selectors fail closed.
- `cmd/cli/request_failover_node_4883_test.go` — OK: a bare node keyword cannot degrade into untargeted failover.
- `cmd/cli/request_wireguard_test.go` — OK: key generation remains local and does not issue a daemon action.
- `cmd/cli/rollback_3447_test.go` — OK: negative/invalid rollback selection is rejected.
- `cmd/cli/show_bgp_firewall_effective_4967_test.go` — OK: aliases and effective compiled-firewall topic mapping are pinned.
- `cmd/cli/show_cluster_typo_5459_test.go` — OK: unknown cluster subarguments fail rather than broaden output.
- `cmd/cli/show_events_zone_3547_test.go` — OK: zone/count/action/protocol filters reach the daemon without being dropped.
- `cmd/cli/show_flow_summary_5320_5323_test.go` — OK: summary completeness/cap metadata is rendered.
- `cmd/cli/show_flowsession_3439_test.go` — OK: malformed numeric selectors and incompatible actions are rejected.
- `cmd/cli/show_matchpolicies_port_3354_test.go` — OK: malformed/out-of-range destination ports issue no RPC.
- `cmd/cli/show_matchpolicies_test.go` — OK: server default verdict and host-inbound SSOT warning are rendered truthfully.
- `cmd/cli/show_policies_metadata_3672_test.go` — OK: exclusion sense, logging, scheduler inactivity, and counted-zero metadata remain visible.
- `cmd/cli/show_policies_scoped_global_3357_test.go` — OK: filtered/brief global scope uses per-rule zone sets and excludes off-pair globals.
- `cmd/cli/show_rollback_int32_5052_test.go` — OK: read-only rollback selectors cannot wrap to another slot.
- `cmd/cli/show_security_selector_4908_test.go` — OK as a regression test, but incomplete by itself: missing zone values are covered; unknown/duplicate inventory selectors remain the deduplicated prior review 175 root.
- `cmd/cli/show_wireguard_test.go` — OK: public-key/detail topics are distinct and stable.
- `cmd/cli/show_zones_hostinbound_3654_test.go` — OK for split fields, exact overrides, and default-deny posture. It lacks physical-parent plus unit inheritance coverage; that gap is the documented deferred `#3720` M07/L05 residue and was suppressed.
- `cmd/cli/show_zones_polerr_3669_test.go` — OK: partial zone output returns nonzero when policy inventory is unavailable.
- `cmd/cli/show_zones_tiers_3683_test.go` — OK: zone-pair, applicable global, and default tiers render in evaluation order; off-zone scoped globals stay hidden.
- `cmd/cli/signal_configmode_5053_test.go` — OK: signal exit bounds configure-session cleanup.
- `cmd/cli/testpolicy_port_test.go` — OK: malformed/out-of-range destination ports fail before legacy topic emission.
- `cmd/cli/testpolicy_protocol_test.go` — OK: protocol names/numbers and invalid values use the shared parser.
- `cmd/cli/testpolicy_srcport_test.go` — OK: source-port validation and topic encoding reviewed.
- `cmd/cli/usage_matchpolicies_3628_test.go` — OK: selector usage is shared across typed policy tools.

### Daemon / Upgrade Command Tooling

- `cmd/shimverify/main.go` — OK: exact arity, verifier-reject exit code, and no-production-state contract reviewed.
- `cmd/xpfd/main.go` — OK: command classification rejects unknown positional verbs; check-config reads regular files through a 4 MiB hard bound and uses strict parse/schema/compile plus device-map preflight; daemon flags preserve explicit sampling gates.
- `cmd/xpfd/publish_generation.go` — OK: leftover args fail before lock/mutation; lock busy defers; unreadable/malformed journal skips destructive GC; pinned generations are protected.
- `cmd/xpfd/seed_runtime.go` — OK: argument arity, side-effect-free capability probe, and versioned runtime seeding reviewed.
- `cmd/xpfd/upgrade.go` — OK: leftover operands reject, cluster nodes require rolling cut, helper health checks forwarding/version, defaults are bounded, and lock/journal ownership lives in the upgrade package.
- `cmd/xpfd/upgrade_kernel.go` — OK: per-verb arity is checked before lock/action; arm/promote/drain/rejoin serialize; promotion fails closed and drain/rejoin use strong predicates.
- `cmd/xpfd/check_config_bounded_4909_test.go` — OK: regular-file and max+1 allocation bounds cover the TOCTOU shape.
- `cmd/xpfd/dispatch_test.go` — OK: recognized, daemon, and unknown top-level routing is pinned.
- `cmd/xpfd/leftover_args_5322_test.go` — OK: cleanup/seed/publish/kernel verbs reject discarded operands before side effects.
- `cmd/xpfd/publish_generation_gc_4876_test.go` — OK: unknown journal protection state suppresses GC; valid pins survive.
- `cmd/xpfd/upgrade_args_4869_test.go` — OK: mistyped rolling/positionals reject and valid flags parse.
- `cmd/xpfd/upgrade_helper_health_5286_test.go` — OK: production construction consults helper armed/forwarding/version state, not systemd activity alone.

### Evidence Probes

- `docs/pr/812-tx-latency-histogram/evidence/vdso_probe.c` — OK, non-production evidence: bounded vDSO timing probe; no policy/API contract.
- `docs/pr/812-tx-latency-histogram/evidence/vdso_probe2.c` — OK, non-production evidence: alternate timing probe; no forwarding or command reachability.


## A10-b2


- `pkg/cli/app_resolve.go`: Reviewed legacy application/address display resolution, protocol/port range handling, and nil address-book behavior; dead helpers are bounded and no live parity defect was retained.
- `pkg/cli/apply.go`: Traced CLI fallback apply ordering, stable zone-ID publication, tunnel/FRR/IPsec errors, and production callback bypass; no new admission or HA-publication root survived.
- `pkg/cli/apply_syslog_zonemap_3704_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/chrony.go`: Reviewed chrony rendering and service-state error handling; no resource or truthfulness defect retained.
- `pkg/cli/chrony_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli.go`: Reviewed construction, RBAC identity, run-loop cancellation, prompts, and signal handling; `go vet`'s line-511 unreachable return is pre-existing and operationally inert.
- `pkg/cli/cli_activate_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_clear.go`: Traced counter/session/NAT/peer clear parsing, reverse-key construction, partial-error aggregation, and peer proxying; no unintended broad clear or silent success retained.
- `pkg/cli/cli_clear_errors_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_clear_flow_display_reject_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_clear_reversekey_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_commit_4868_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_commit_confirm_pending_4000_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_commit_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_config.go`: Traced strict commit/check/confirmed/comment parsing, timeout cancellation, load sources, rollback display, secret redaction, and daemon apply callbacks; no fail-open commit path retained.
- `pkg/cli/cli_config_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_dispatch.go`: Reviewed prefix resolution, RBAC gate, config/operational split, streaming filters, pager bounds, and stdout lifecycle; nested pager under show-pipe is exact prior root codex-review-178 and suppressed.
- `pkg/cli/cli_dispatch_pager_stream_4709_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_dispatch_pipe_stream_4731_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_display_fidelity_4908_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_helpers.go`: Reviewed interface identity assembly, runtime adapters, nil handling, and formatting; no new defect retained.
- `pkg/cli/cli_last_cap_5037_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_matchpolicies_scheduler_3414_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_request.go`: Reviewed request-family routing and FRR/DHCP control calls; fixed command strings avoid injection and errors are surfaced.
- `pkg/cli/cli_request_argv_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_request_chassis.go`: Reviewed failover and userspace control parsing, maintenance classification call path, and status prerequisites; no destructive abbreviation bypass retained.
- `pkg/cli/cli_request_ping.go`: Reviewed argv construction, end-of-options handling, contexts, and result propagation for ping/traceroute; no injection or unbounded execution retained.
- `pkg/cli/cli_request_policies_check.go`: Reviewed shadow-policy diagnostic ordering, excluded-address sense, scoped/global behavior, and scheduler semantics; no enforcement claim or new mismatch retained.
- `pkg/cli/cli_request_policies_check_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_request_security.go`: Reviewed IPsec/policy/WireGuard request dispatch and manager absence behavior; no privilege or fail-open policy mutation retained.
- `pkg/cli/cli_request_system.go`: Reviewed destructive confirmations, zeroize completeness, archive/config erasure, ISSU takeover fence, DDNS, and rescue operations; no new reachable destructive bypass retained.
- `pkg/cli/cli_request_system_issu_5039_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_request_testcmd.go`: Traced shared policy simulator tiers/default/host-inbound/content rejection, dynamic feeds, scheduler state, routing lookup, and zone interface display; no simulator admission mismatch retained.
- `pkg/cli/cli_request_wireguard_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_rollback_3447_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show.go`: Reviewed show dispatch, redacted configuration formats, effective-filter selection, and service/tool surfaces; no new secret exposure retained.
- `pkg/cli/cli_show_appset_nil_5221_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_chassis.go`: Reviewed forwarding status adapters and local/remote display fallback; no false healthy state retained.
- `pkg/cli/cli_show_chassis_adapter_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_cluster.go`: Reviewed cluster role/interface/fabric counters, userspace fairness/flows, and hardware/environment readers; failures remain diagnostic and bounded.
- `pkg/cli/cli_show_cluster_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_config_redaction_4099_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_dynamic_address_redaction_5521_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_effective_filter_4422_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_effective_filter_gen_5067_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_flow.go`: Reviewed session filters, reverse direction, limits, summaries, top talkers, timeouts, trace, cache/session statistics, and userspace max-session display; no new tuple or bound defect retained.
- `pkg/cli/cli_show_flow_summary_5323_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_flow_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_interfaces.go`: Reviewed physical/logical/RETH/VLAN identity, configured-vs-kernel names, host-inbound presentation, and nil config/interface handling; no zone attribution defect retained.
- `pkg/cli/cli_show_interfaces_detail.go`: Reviewed logical-unit address and counter detail, netlink failures, and host-inbound effective view; no false policy claim retained.
- `pkg/cli/cli_show_interfaces_extensive.go`: Reviewed extensive counters, logical units, queue/runtime stats, and netlink error paths; no new resource or identity defect retained.
- `pkg/cli/cli_show_interfaces_identity_4984_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_interfaces_nil_5068_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_interfaces_reth_4328_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_interfaces_shared.go`: Reviewed shared kernel-name/operstate helpers and nil behavior; no issue retained.
- `pkg/cli/cli_show_interfaces_stats.go`: Reviewed configured-unit selection and counter aggregation; no duplicate or wrong-unit count retained.
- `pkg/cli/cli_show_interfaces_terse.go`: Reviewed RETH/logical identity, family/address rendering, operstate, and stable dimensions; no new display denial/admission ambiguity retained.
- `pkg/cli/cli_show_log_cap_5069_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_logical_unit_5325_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_nat.go`: Reviewed source/destination/static/persistent/NAT64/NPTv6/CGNAT inventory and counters, nils, alarms, and userspace caveats; no new NAT order or policy claim retained.
- `pkg/cli/cli_show_nat_shared_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_nat_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_policies_bulk_reader_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_policies_hitcount_gate_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_policies_scheduler_3062_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_policies_thencount_3074_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_routing.go`: Reviewed route/VRF/protocol/neighbor/PBR-facing displays, best-prefix selection, IPv4/IPv6 handling, and partial netlink failures; no new forwarding claim retained.
- `pkg/cli/cli_show_security.go`: Reviewed policy counter handles versus runtime IDs, scoped global/default rows, exclusions, application details, scheduler state, and match-policy output; counter namespaces remain intentionally distinct and coherent.
- `pkg/cli/cli_show_security_dispatch.go`: Reviewed policy/zone/security command grammar and all dispatch branches; retained malformed zone-selector widening finding.
- `pkg/cli/cli_show_security_filters.go`: Reviewed configured/effective filters, term counters, family parsing, helper generation/armed liveness, and compiled-desired warnings; no false live certification retained.
- `pkg/cli/cli_show_security_flat_zone_local_3358_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_ipsec.go`: Reviewed IKE/IPsec SA/status/statistics presentation and manager errors; no new completeness defect retained in assigned surface.
- `pkg/cli/cli_show_security_log.go`: Reviewed live/historical security log parsing, zone labels, negative args, alarms, and nil event sources; no silent historical-zone loss retained.
- `pkg/cli/cli_show_security_log_argparse_3347_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_log_historical_zone_3335_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_log_negative_3342_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_nil_3476_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_objects.go`: Reviewed address books, application/app-set nils, dynamic feed URL redaction, and recursive display boundaries; no secret or nil defect retained.
- `pkg/cli/cli_show_security_policy_addr_excluded_3336_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_policy_index_3063_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_scoped_global_3286_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_scoped_global_3357_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_screen.go`: Reviewed complete screen inventory, enabled checks, thresholds, zone selection, unavailable userspace per-zone counters, and read errors; no false enforcement claim retained.
- `pkg/cli/cli_show_security_screen_inventory_3327_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_wireguard.go`: Reviewed userspace-only tunnel/public-key telemetry and unavailable status behavior; no secret output retained.
- `pkg/cli/cli_show_security_wireguard_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_zone_local_3358_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_zones.go`: Reviewed stable zone IDs, host-inbound defaults/overrides/lifelines, screen metadata, all three policy tiers/default, logical-unit addresses, and unavailable counters; no policy-tier omission retained.
- `pkg/cli/cli_show_security_zones_explicit_any_3680_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_zones_metadata_3684_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_security_zones_policy_tiers_3658_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_services.go`: Reviewed DHCP/SNMP/LLDP/service inventory, nil managers, and empty states; no new operational misstatement retained.
- `pkg/cli/cli_show_services_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_shared.go`: Reviewed shared help rendering; no issue retained.
- `pkg/cli/cli_show_snmp_community_redaction_4111_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_show_system.go`: Reviewed buffers, services, syslog, login/secret redaction, bounded log reads, rollback/rescue, process/storage/users views, and allowlisted log paths; no new exposure retained.
- `pkg/cli/cli_show_system_buffers_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cli_zone_nil_3493_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/cluster_failover_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/completion.go`: Reviewed tree prefix ambiguity, typed leaf values, candidate bounds, pipe completion, and nil schema/config paths; no panic or command-resolution bypass retained.
- `pkg/cli/completion_activate_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/completion_panic_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/completion_typed_leaf_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/configstore_helper_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/host_inbound_display_3654_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/link.go`: Reviewed sysfs speed/duplex reads and formatting; names originate from resolved interfaces and errors degrade to unknown.
- `pkg/cli/monitor.go`: Reviewed trace path confinement, atomic parser updates, file/count bounds, subscription lifecycle, filtering, writer failures, packet-drop parsing, and locks; prior stop/join lifecycle root is deduplicated.
- `pkg/cli/monitor_flow_perm_5038_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_flow_writer_stop_4883_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_interface.go`: Reviewed terminal mode restore, key-reader shutdown, configured/kernel/RETH identity, snapshots, and traffic loops; no goroutine/resource leak retained.
- `pkg/cli/monitor_interface_stdin_3985_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_match_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_nil_eventbuf_3381_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_security_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_traffic.go`: Reviewed strict interface/filter/count parsing, option-token denial, argv construction, context cancellation, and tcpdump child lifecycle; no argument injection or unbounded count retained.
- `pkg/cli/monitor_traffic_count_bound_4589_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_traffic_filter_4005_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.
- `pkg/cli/monitor_traffic_injection_4524_test.go`: Reviewed the regression's positive/negative assertions and production seam; it covers the named behavior without masking an additional independent root.

Supporting (not batch-owned) call sites read-only reviewed: `pkg/cli/permissions.go`, `pkg/cmdtree`, `pkg/configstore`, `pkg/policymatch`, `pkg/dataplane/userspace/policies_ids.go`, `pkg/dataplane/userspace/policycounters.go`, and `pkg/daemon/daemon_run.go`.


## A10-b3


Legend: `C/S` correctness, security, allow/deny and fail-closed; `M/R` memory, concurrency and resources; `VP` vSRX/operational parity; `T` tests. Every assigned path is recorded below.

### CLI and operational display

- `pkg/cli/monitor_traffic_keyword_4540_test.go` - T negative keyword/value parsing reviewed; prevents an omitted operand from becoming a broad capture.
- `pkg/cli/monitor_traffic_matching_4883_test.go` - T empty/typo matching predicates fail closed.
- `pkg/cli/monitor_traffic_quotestrip_4556_test.go` - T quote stripping does not turn tcpdump options into accepted filters.
- `pkg/cli/peer.go` - C/S fabric auth rotates per RPC, VRF binding is applied to probe and gRPC dial, addresses are bounded by 2s probes; no new defect.
- `pkg/cli/peer_endpoint_4909_test.go` - T IPv6 endpoint bracketing covered.
- `pkg/cli/peer_fabric_auth_5324_test.go` - T armed/unarmed keyed fabric cases and daemon scheme parity covered.
- `pkg/cli/permissions.go` - C/S RBAC resolves custom classes, fails unknown classes closed, prefix-resolves privileged verbs, redacts non-super-user secrets; no bypass found.
- `pkg/cli/permissions_custom_class_4304_test.go` - T custom-class permit/deny and reset/zeroize denial covered.
- `pkg/cli/permissions_dataplane_maint_4859_test.go` - T destructive dataplane verbs and abbreviations require maintenance.
- `pkg/cli/permissions_maintenance_4108_test.go` - T destructive system/chassis verbs require maintenance while benign controls remain available.
- `pkg/cli/permissions_monitor_traffic_4067_test.go` - T packet capture requires control and ordinary monitoring remains view-only.
- `pkg/cli/policymatch_dup_3709_test.go` - C/S duplicate query selectors are rejected rather than last-wins broadened.
- `pkg/cli/policymatch_feed_overlay_test.go` - VP dynamic feed overlay participates in policy simulation.
- `pkg/cli/policymatch_port_test.go` - C/S malformed ports fail both simulator surfaces.
- `pkg/cli/policymatch_protocol_test.go` - C/S malformed protocols fail both simulator surfaces.
- `pkg/cli/proto.go` - C/S protocol conversion reviewed for ICMPv4/v6 and numeric fallback; no allow/deny mismatch found.
- `pkg/cli/query_strictness_3696_test.go` - T strict unknown/duplicate selector behavior covered.
- `pkg/cli/runtime.go` - M/R narrow runtime interface only, no ownership or hot-path behavior; iterator/error contracts represented.
- `pkg/cli/session_display.go` - VP egress interface keys include ifindex and VLAN/unit fallback; nil config and lookup failures degrade without guessing.
- `pkg/cli/session_display_test.go` - T VLAN fallback, parent/interface matching and v4 display mapping covered.
- `pkg/cli/session_filter.go` - C/S parser records all unknown/missing values, clear-mode modifiers fail closed, v4/v6 byte order and NAT/app/interface matching align; RPCs are timeout-bounded.
- `pkg/cli/session_filter_multi_iface_4792_test.go` - VP v4/v6 multi-interface zone matching covered.
- `pkg/cli/session_filter_test.go` - T SNAT pool, byte order, validation, peer-clear projection and parse errors covered.
- `pkg/cli/sessions_iterator_error_test.go` - C/S partial iterator results are not rendered as complete.
- `pkg/cli/show_interfaces_queue_5326_test.go` - VP distinguishes helper error, empty snapshot and populated snapshot.
- `pkg/cli/show_log_allowlist_4860_test.go` - C/S log-path allowlist rejects arbitrary paths.
- `pkg/cli/show_security_counter_error_test.go` - VP broad counter-read failure matrix avoids clean-zero claims on degraded reads.
- `pkg/cli/show_services_cos.go` - VP CoS display is snapshot/status only and propagates unavailable/error states; no unbounded work beyond configured queues.
- `pkg/cli/show_services_ddns.go` - VP degraded fail-closed state, pending ownership and counters are visible; provider names are sorted.
- `pkg/cli/show_services_dhcp.go` - VP client/relay/server state surfaces read failures and relay security counters; map ordering is cosmetic only.
- `pkg/cli/show_services_lldp.go` - VP disabled/default timing and neighbor state are represented; bounded by neighbor-table ownership elsewhere.
- `pkg/cli/show_services_mirror.go` - VP configured mirror instances are displayed without claiming runtime health.
- `pkg/cli/show_services_snmp.go` - C/S communities redact for all non-super-user/unknown classes; v3 secrets are not printed.
- `pkg/cli/testpolicy_icmp_4497_test.go` - VP queried ICMP type/code echo covered.
- `pkg/cli/testpolicy_idscope_3674_test.go` - VP policy identity/scope description covered.
- `pkg/cli/testpolicy_srcport_test.go` - C/S source-port matching and invalid input covered.
- `pkg/cli/usage_matchpolicies_3628_test.go` - VP supported selectors are accurately advertised.
- `pkg/cli/zone_flood_counters_hide_test.go` - VP unavailable flood counters are hidden rather than fabricated.

### DDNS

- `pkg/ddns/backend.go` - C/S backend interface, no-op classification and host-record family/type construction reviewed; invalid addresses fail.
- `pkg/ddns/backend_bind.go` - C/S source-family and SO_BINDTODEVICE resolution fail closed when requested binding cannot be honored.
- `pkg/ddns/backend_bind_test.go` - T source/device/VRF precedence, resolver, family gate and device validation covered.
- `pkg/ddns/backend_cloudflare.go` - C/S paginated exact name/type/content ownership operations preserve foreign rows; HTTP work bounded.
- `pkg/ddns/backend_cloudflare_pagination_4909_test.go` - T multi-page record lookup covered.
- `pkg/ddns/backend_cloudflare_test.go` - T create/update/renumber/delete, ownership conflict, auth and missing credentials covered.
- `pkg/ddns/backend_dualstack_withdraw_3738_test.go` - C/S host-granular withdraw preserves an owned sibling family.
- `pkg/ddns/backend_duckdns.go` - C/S request construction and whole-host withdraw semantics reviewed with sibling guard; bounded HTTP.
- `pkg/ddns/backend_duckdns_test.go` - T v4/v6 request, clear, verdict, credentials and label handling covered.
- `pkg/ddns/backend_dyndns2.go` - C/S endpoint validation, verdict parsing, credential scrubbing and offline withdraw reviewed.
- `pkg/ddns/backend_generic.go` - C/S template URL validation, token-boundary success matching and explicit unsupported-delete error reviewed.
- `pkg/ddns/backend_generic_porthost_4589_test.go` - T malformed port-only host rejected.
- `pkg/ddns/backend_http.go` - M/R transport timeouts, redirect cap/downgrade refusal, 64 KiB response cap and cache reap reviewed; the ownership-state loader finding is separate.
- `pkg/ddns/backend_http_sourcebind_2846_test.go` - T bound/unbound transport and invalid-source behavior covered.
- `pkg/ddns/backend_http_test.go` - T provider verdicts, endpoint parsing, real deletes, template validation and exact success tokens covered.
- `pkg/ddns/backend_rfc2136.go` - C/S TSIG, exact-RR ownership, prerequisites, caller cancellation and UDP-to-TCP retry reviewed; unsigned mode is explicitly warned.
- `pkg/ddns/backend_rfc2136_test.go` - T forward/reverse v4/v6, ownership conflicts, TSIG, timeout, PTR deferral and TCP cancellation covered.
- `pkg/ddns/backend_route53.go` - C/S current read-modify-write preserves foreign RRset members and exact delete semantics; residual provider race is documented, no new root.
- `pkg/ddns/backend_route53_test.go` - T foreign-member preservation, renumber, idempotency, ownership conflict and genuine errors covered.
- `pkg/ddns/backend_sourcefamily_5327_test.go` - C/S cross-family HTTP/RFC2136 source binding fails closed.
- `pkg/ddns/checkip.go` - C/S URL/status/public-address/allowlist gates reviewed; requests are timeout/body bounded and bind failure suppresses publication.
- `pkg/ddns/checkip_sourcebind_failclosed_3733_test.go` - T wrong-egress fallback suppression covered.
- `pkg/ddns/checkip_test.go` - T special-purpose ranges, allowlist, malformed URL and mock HTTP behavior covered.
- `pkg/ddns/corrupt_state_durable_4873_test.go` - T degraded marker survives quarantine/restart; does not cover oversized input (finding A10-b3-F001).
- `pkg/ddns/durability_test.go` - T write-ahead order and pre-add save failure suppression covered.
- `pkg/ddns/hostname.go` - C/S DNS label/FQDN normalization is length-bounded and validates rather than silently changing accepted hostnames.
- `pkg/ddns/manager.go` - C/S/M reconcile, ownership, expiry, backoff and provider I/O lock release reviewed; state-load resource risk traces to `state.go`.
- `pkg/ddns/manager_inc2_test.go` - T live backend lifecycle, disable/removal, conflicts, PTR pending and ownership views covered.
- `pkg/ddns/manager_lockio_5006_test.go` - M provider upsert/delete do not hold manager mutex.
- `pkg/ddns/manager_test.go` - T name derivation, ownership moves, delete-before-replace, corruption and retry behavior covered.
- `pkg/ddns/redirect_downgrade_4861_test.go` - C/S redirect downgrade and client wiring covered.
- `pkg/ddns/scope_test.go` - C/S v4/v6 and RG scope isolation plus unattributable fail-closed gate covered.
- `pkg/ddns/sigv4.go` - C/S canonical request/query/header and key derivation reviewed; secrets stay out of errors.
- `pkg/ddns/sigv4_test.go` - T known vector and canonical query coverage.
- `pkg/ddns/spine_fixes_test.go` - T shared DHCID, no-backend ownership retention and PTR visibility covered.
- `pkg/ddns/state.go` - C/S semantic/version/degraded handling is fail closed and writes are durable; unbounded pre-validation read is A10-b3-F001.
- `pkg/ddns/state_semantic_4909_test.go` - T malformed address rejection and durable cleanup covered; no size-bound case.
- `pkg/ddns/surface_a.go` - C/S/M durable pending publication, exact withdraw, provider identity, RG gate, backoff and unlocked I/O reviewed; no admission policy path.
- `pkg/ddns/surface_a_durable_pending_5285_test.go` - T crash windows and happy-path confirmation covered.
- `pkg/ddns/surface_a_hostname_2779_test.go` - T validator/sanitizer agreement covered.
- `pkg/ddns/surface_a_http_test.go` - T real HTTP engine, backoff, secret non-disclosure, no-backend and status rows covered.
- `pkg/ddns/surface_a_httpcache_2904_test.go` - M transport reuse and binding-change rebuild covered.
- `pkg/ddns/surface_a_httpcache_reap_2956_test.go` - M superseded transport close and live-cache bound covered.
- `pkg/ddns/surface_a_lockio_test.go` - M unlocked provider operations and racing newer-state guard covered.
- `pkg/ddns/surface_a_observe_lockio_3736_test.go` - M unlocked observation and context cancellation covered.
- `pkg/ddns/surface_a_provider_change_3735_test.go` - C/S endpoint mutation/rename orphan alarms, adoption and secret-free fingerprint covered.
- `pkg/ddns/surface_a_provider_transition_4422_test.go` - C/S clean configured-provider handoff and steady-state no-withdraw covered.
- `pkg/ddns/surface_a_rfc2136_test.go` - C/S real backend exact ownership, foreign preservation, withdraw and RG gate covered.
- `pkg/ddns/surface_a_sourcebind_failclosed_4437_test.go` - C/S cached bind error suppresses backend publication.
- `pkg/ddns/surface_a_test.go` - T publish/refresh/backoff/FQDN migration/degraded/restart ordering and total sorting covered.
- `pkg/ddns/surface_a_withdraw_backoff_2813_test.go` - M failed/unsupported withdraw backoff and retry covered.
- `pkg/ddns/surface_a_withdraw_pending_5334_test.go` - C/S both crash-window candidates and sibling preservation covered.

### Device map, DHCP client and DHCP relay

- `pkg/devicemap/devicemap.go` - C/S deterministic PCI/permanent-MAC matching rejects ambiguity, duplicate claims and virtual/non-hardware devices; sysfs errors do not guess.
- `pkg/devicemap/devicemap_nonpci_4884_test.go` - T non-PCI hardware classification and MAC-only binding covered.
- `pkg/devicemap/devicemap_test.go` - T ambiguity, mismatch, fallback, slot swap, duplicate NIC and reorder determinism covered.
- `pkg/dhcp/classless_routes_test.go` - VP RFC3442/249 precedence and encoding covered.
- `pkg/dhcp/clearduid_traversal_4857_test.go` - C/S DUID clear path traversal rejected.
- `pkg/dhcp/commit.go` - C/S lease/PD commit change detection and callback lock discipline reviewed; no partial-state widening.
- `pkg/dhcp/commit_test.go` - T renewal timers, content changes, initial/stateless lease and PD callbacks covered.
- `pkg/dhcp/dhcp.go` - M client registration/replacement, cancellation joins, DUID validation/durability and lease cleanup reviewed; finite interface/config cardinality bounds maps.
- `pkg/dhcp/dhcp_lease_expiry_4874_test.go` - T terminal recompile, timeout retention and PD withdrawal covered.
- `pkg/dhcp/dhcp_test.go` - T PD extraction/subprefix/options coverage.
- `pkg/dhcp/dhcpv6_iana_test.go` - C/S deterministic multi-IA address selection covered.
- `pkg/dhcp/duid_cohort_4909_test.go` - T persisted cohort clear/error and DUID-LLT persist failure covered.
- `pkg/dhcp/gateway_hook_test.go` - M gateway callback matrix, successor guard and concurrency covered.
- `pkg/dhcp/reconcile.go` - M desired-set diff, stop-before-restart and option-state pruning reviewed; starts occur outside lock.
- `pkg/dhcp/reconcile_test.go` - T add/remove/restart/terminal exit/renew race/StopAll behavior covered.
- `pkg/dhcp/renew.go` - C/S renewal request construction, destination and timer selection reviewed.
- `pkg/dhcp/renew_test.go` - T v4/v6 renew/rebind, NAK restart and degenerate mask rejection covered.
- `pkg/dhcp/test_seams.go` - T-only synchronized seams return snapshots and do not affect production.
- `pkg/dhcprelay/delivery_test.go` - C/S reply matrix, NAK/FORCERENEW, saved giaddr and configured-source allowlist covered.
- `pkg/dhcprelay/l2send_linux.go` - C/S raw Ethernet/IPv4/UDP construction checks lengths/MTU and checksums; socket ownership/close reviewed.
- `pkg/dhcprelay/l2send_test.go` - T per-byte frame, checksum and close/open seams covered.
- `pkg/dhcprelay/relay.go` - C/S/M 65,535-byte reads, hop bound, giaddr/Option82 trust, HA gate, server allowlist, cancellation joins and rebind loops reviewed; no novel root.
- `pkg/dhcprelay/relay_chain_5071_test.go` - C/S first-hop/chained/trusted and forged-giaddr behavior covered.
- `pkg/dhcprelay/relay_giaddr_linux.go` - C/S netlink primary-address selection falls back deliberately and never manufactures an address.
- `pkg/dhcprelay/relay_giaddr_linux_test.go` - T primary/secondary order, fallback and empty cases covered.
- `pkg/dhcprelay/relay_test.go` - T broad request types, oversized datagrams, lifecycle, retries, drift/readdress, HA gate and bounded stop coverage.
- `pkg/dhcprelay/sockopt_linux.go` - C/S pre-bind REUSEPORT/BROADCAST/SO_BINDTODEVICE setup reviewed; errors abort socket construction.


## A10-b4


### DHCP server, DDNS, and HA lease synchronization

- `pkg/dhcpserver/ddns.go` — DDNS adapter; checked v4/v6 lease-kind conversion and destructive-reconcile error direction; no new issue.
- `pkg/dhcpserver/ddns_iapd_5072_test.go` — DDNS IA_PD exclusion regression; positive/negative lease-kind cells present; no gap found.
- `pkg/dhcpserver/ddns_integration_test.go` — parser-to-reconciler integration and family trust; destructive-empty posture covered; no gap found.
- `pkg/dhcpserver/ddns_leases.go` — strict Kea memfile parsing; checked header/row validation, active/tombstone precedence, identity, expiry, IA_PD, integer parsing, and stable dedup; no new issue.
- `pkg/dhcpserver/ddns_leases_test.go` — malformed/headerless/duplicate/ragged rows, reclaim, identity, and lease-type matrix; substantive negative result: destructive diff inputs fail closed.
- `pkg/dhcpserver/dhcpserver.go` — systemd reconcile, generated v4/v6 config, async generation ordering, display parser, subnet IDs, and atomic writes; no new issue.
- `pkg/dhcpserver/dhcpserver_isactive_error_4870_test.go` — uncertain service state forces authoritative restart/stop and surfaces error; no gap found.
- `pkg/dhcpserver/dhcpserver_test.go` — apply ordering, generation, config rendering, lease display leniency, subnet collisions, and service lifecycle; no new issue.
- `pkg/dhcpserver/expired_leases_test.go` — append-log state/expiry/reallocation truth table; no stale display regression found.
- `pkg/dhcpserver/lease_sync.go` — Kea control protocol, memfile fallback, v4/v6 identity, merge, seed, owner, and atomic file lifecycle; no new issue.
- `pkg/dhcpserver/lease_sync_test.go` — socket framing/errors, merge precedence, IA_NA/IA_PD, CSV quoting, ownership and fallback coverage; no new issue.
- `pkg/dhcpserver/reservations_test.go` — deterministic reservation/config emission and MAC handling; no collision or order issue found.
- `pkg/dhcpserver/test_seams.go` — test-only global seam reset/serialization; no production exposure or race found.

### Diagnostics, fairness, and filesystem/socket primitives

- `pkg/diagcmd/diagcmd.go` — argv construction; checked VRF normalization and end-of-options injection resistance; no new issue.
- `pkg/diagcmd/diagcmd_test.go` — exact ping/traceroute argv and prefixed VRF cases; no gap found.
- `pkg/diagcmd/limiter.go` — process-wide bounded semaphore and idempotent release; resource bound is fixed and nonblocking; no new issue.
- `pkg/diagcmd/limiter_test.go` — cap, double-release, and concurrent admission tests; no leak/over-release found.
- `pkg/fairness/expectation.go` — expectation parsing/evaluation; checked NaN/Inf, percent ranges, uint accumulation, zero-flow and balanced math; no new issue.
- `pkg/fairness/expectation_test.go` — parser and evaluator positive/negative cells; no arithmetic edge gap found.
- `pkg/fsatomic/canary_test.go` — call-site/persistence-class canary; no unapproved writer drift reported.
- `pkg/fsatomic/fsatomic.go` — temp/rename/fsync, symlink, mode/owner, post-rename error and cleanup lifetimes; no new issue.
- `pkg/fsatomic/fsatomic_test.go` — injected failure stages, durability, symlinks, ownership and concurrent writers; no missing critical stage found.
- `pkg/fsatomic/test_seams.go` — post-rename sync test seam; scoped restore contract is sound.
- `pkg/linuxsock/canary_test.go` — socket-option ownership canary; no direct-syscall drift found.
- `pkg/linuxsock/linuxsock.go` — `SO_BINDTODEVICE` wrapper; checked fd lifetime and error propagation; no new issue.
- `pkg/linuxsock/linuxsock_test.go` — valid/invalid fd and kernel option behavior; no gap found.

### Forwarding status and interface monitor

- `pkg/fwdstatus/builder.go` — liveness, uptime, CPU/memory denominators and userspace status mapping; no divide/overflow or false-online issue found.
- `pkg/fwdstatus/fwdstatus.go` — stable status rendering and clamping; no output ambiguity found.
- `pkg/fwdstatus/fwdstatus_test.go` — online/degraded/unknown, CPU windows, memory and formatting matrix; no gap found.
- `pkg/fwdstatus/osprocreader_test.go` — `/proc` malformed/live parsing; no parser panic path found.
- `pkg/fwdstatus/procreader.go` — `/proc` and cgroup parsing; checked field indexing, scanner errors, and byte multiplication; no new issue.
- `pkg/fwdstatus/sampler.go` — cached status sampling, monotonic ring, reset guards and window math; no control-socket hot-path regression found.
- `pkg/fwdstatus/sampler_test.go` — cache miss, rollover/window, nonmonotonic and render tests; no gap found.
- `pkg/fwdstatus/ticks_overflow_4909_test.go` — tick-to-nanosecond overflow regression; covered.
- `pkg/monitoriface/monitor.go` — kernel/userspace aggregation, alias/RETH/fabric identity, deltas/rates and rendering; no double-source or underflow issue found.
- `pkg/monitoriface/monitor_test.go` — aggregation, naming, modes, resets and output tests; no new gap found.

### IP monitoring and LLDP

- `pkg/ipmon/display.go` — policy state output; checked unknown/pending/applied/unresolved/suppressed distinctions; no new issue.
- `pkg/ipmon/ipmon.go` — HA publication, winner resolution, debounce/throttle, dirty generation, timeout and lock lifecycle; no new issue.
- `pkg/ipmon/ipmon_test.go` — failure/recovery, hold-down, retries, publish gate and shutdown matrix; no lost-dirty transition found.
- `pkg/ipmon/nexthop_test.go` — DHCP next-hop resolution, withdrawal and winner fallback; no stale gateway issue found.
- `pkg/lldp/lifecycle_mutex_5121_test.go` — concurrent lifecycle serialization regression; no double-close/start found.
- `pkg/lldp/lldp.go` — raw socket lifetime, apply/stop, RX retry, neighbor cap, TTL=0, TLV bounds/sanitization and endian conversion; no new issue.
- `pkg/lldp/lldp_test.go` — frame/TLV/parser/neighbor/lifecycle coverage; no malformed mandatory-TLV admission found.
- `pkg/lldp/shutdown_ttl0_5123_test.go` — immediate withdrawal truth table; no expiry-delay regression found.
- `pkg/lldp/socket_test.go` — socket setup, close-unblock, transient errors and self-frame filtering; no fd/resource leak found.

### NAT alarms and management display

- `pkg/natpoolalarm/natpoolalarm.go` — coherent sampling, hysteresis, eligibility, lifecycle and locking; no false clear/raise or stop race found.
- `pkg/natpoolalarm/natpoolalarm_test.go` — threshold boundaries, missing/incoherent samples, deterministic pools and lifecycle; no gap found.
- `pkg/natpoolalarm/render.go` — shared summary/detail output and numbering; no CLI/gRPC drift found.
- `pkg/natpoolalarm/render_test.go` — detail/summary/empty output; no gap found.
- `pkg/natpoolalarm/stop_race_4909_test.go` — concurrent stop double-close regression; covered.
- `pkg/natshow/dest.go` — destination-NAT config, counters and v4/v6 session display; checked nil/runtime errors and rule-set aggregation; no security-semantic finding.
- `pkg/natshow/natshow.go` — narrow shared reader contract; no ownership or dependency issue found.
- `pkg/natshow/natshow_test.go` — source/destination/static/persistent output parity and nil paths; no new gap found.
- `pkg/natshow/persistent.go` — v4/v6 persistent keys, byte order, timeout and permit mode; no panic/endianness issue found.
- `pkg/natshow/source.go` — source-NAT config, counters and v4/v6 session display; no new issue.
- `pkg/natshow/static.go` — static/NPTv6 and accepted-but-unenforced routing-instance disclosure; no hidden enforcement claim found.

### Kernel host-inbound counters and RST suppression (Z4 peer)

- `pkg/nftables/host_inbound_accept_counters.go` — global ICMP/ND accept object parsing/readback; prefix/type separation is fail closed; no new issue.
- `pkg/nftables/host_inbound_accept_counters_test.go` — accept names, unknown classes and deny-prefix separation; no gap found.
- `pkg/nftables/host_inbound_counters.go` — coarse zone/family deny naming/readback; checked family/length parsing and absent-table semantics; no new enforcement issue.
- `pkg/nftables/host_inbound_counters_test.go` — reversible safe names, malformed inputs and documented lossy exotic names; no new gap found.
- `pkg/nftables/host_inbound_junos_host_counters.go` — fine junos-host policy-deny counters; checked prefix isolation and family/scope parsing; no coarse/fine conflation found.
- `pkg/nftables/lo0_counters.go` — lo0 named-counter parsing/readback; no cross-prefix or malformed-object admission found.
- `pkg/nftables/lo0_counters_test.go` — round trip, sanitization and malformed names; no gap found.
- `pkg/nftables/rst_suppress.go` — atomic table replacement and IPv4/IPv6 TCP RST expression construction; no open replacement window found.
- `pkg/nftables/rst_suppress_test.go` — empty/replacement plan behavior; no gap found.

### Policy simulator and management parity (Z6 primary)

- `pkg/policymatch/app_icmp_code_4422_test.go` — custom/builtin ICMP type/code attribution and swapped-pair negatives; no drift found.
- `pkg/policymatch/app_junos_ping_3348_test.go` — custom junos-ping echo-only semantics; no over-permit found.
- `pkg/policymatch/app_set_failclosed_3727_test.go` — malformed app-set whole-snapshot rejection; no default-permit leak found.
- `pkg/policymatch/app_srcdst_port_range_4413_test.go` — simultaneous source/destination ranges; no range-axis drift found.
- `pkg/policymatch/content_reject_4394_test.go` — unrepresentable app/address config-wide rejection; strict/lenient runtime posture aligned.
- `pkg/policymatch/display_action_3375_test.go` — matched/default/host action SSOT; no blank transport verdict found.
- `pkg/policymatch/empty_zone_4411_test.go` — empty zone resolves unknown/default, not wildcard; no fail-open found.
- `pkg/policymatch/excluded_addr_3356_test.go` — empty-excluded and cross-family exclusion truth table; no false permit/deny found.
- `pkg/policymatch/excluded_response_3668_test.go` — exclusion flags and stable response identity; no inverted display found.
- `pkg/policymatch/global_scope_regression_4365_test.go` — scoped-global precedence and scope sets; no scope widening found.
- `pkg/policymatch/global_zone_filter_3357_test.go` — filtered global inventory applicability; no hidden applicable global found.
- `pkg/policymatch/host_inbound_token_3627_test.go` — service/protocol/global/default host admission classification; no token drift found.
- `pkg/policymatch/host_inbound_verdict_msg_3627_test.go` — host-inbound wording does not assert unconditional delivery; no misleading permit found.
- `pkg/policymatch/icmp_test.go` — ICMP/ICMPv6 type omission/mismatch/unconstrained apps; no parity gap besides F1's fragment dimension.
- `pkg/policymatch/junos_host_test.go` — exact/from-any/global-host precedence and no transit fallback; no new issue.
- `pkg/policymatch/policymatch.go` — full parser, tier walk, host gate, content rejection, addresses, apps, schedulers, result/output and route advisory; **F1**.
- `pkg/policymatch/policymatch_test.go` — core exact/wildcard/global/default, address/feed/app and IDs; no new gap beyond F1.
- `pkg/policymatch/port_omitted_3330_test.go` — omitted destination port skips constrained app; this is one leg of F1's reproducible mismatch.
- `pkg/policymatch/port_test.go` — numeric/alias/range matching; no parse drift found.
- `pkg/policymatch/protocol_omitted_3323_test.go` — omitted protocol fail-closed for constrained apps; no new issue.
- `pkg/policymatch/protocol_test.go` — protocol name/number validation; no alias drift found.
- `pkg/policymatch/reject_matrix_4422_test.go` — permit/deny/reject/default output matrix; no action collapse found.
- `pkg/policymatch/route_drop_4373_test.go` — multicast/broadcast/unspecified/loopback advisory and host exemption; no output drift found.
- `pkg/policymatch/scheduler_test.go` — inactive skip and default fallthrough; no simulator scheduler-state drift found.
- `pkg/policymatch/scope_id_3331_test.go` — numeric/stable policy identity across scopes; no collision found.
- `pkg/policymatch/scoped_global_zonelocal_test.go` — zone-local addresses under scoped globals; no resolution drift found.
- `pkg/policymatch/scoped_global_zoneset_4626_test.go` — multi-zone scope match/report behavior; no false widening found.
- `pkg/policymatch/selector_args_3696_test.go` — strict selector grammar and IP/port/protocol conversion; fragment selector is absent, feeding F1.
- `pkg/policymatch/selector_args_dup_3709_test.go` — duplicate selector rejection; no first/last-win ambiguity found.
- `pkg/policymatch/simulator_output_parity_3685_test.go` — description/scheduler response metadata; no REST/gRPC/CLI field drift found.
- `pkg/policymatch/srcport_omitted_3415_test.go` — omitted source-port fail-closed behavior; no new issue.
- `pkg/policymatch/undefined_zone_3355_test.go` — unknown zone ID-0 behavior across tiers/host; no fail-open found.
- `pkg/policymatch/usage_3628_test.go` — advertised selector set matches parser, but both omit packet-fragment state as described by F1.
- `pkg/policymatch/wildcard_scoped_test.go` — exact/single-wildcard/both-any/global ordering; no tier inversion found.
- `pkg/policymatch/zone_detail_summary.go` — shared zone summary IDs/order/global/default/scheduler/log/count/exclusion; no new issue.
- `pkg/policymatch/zone_detail_summary_test.go` — metadata, unknown scheduler state, wildcard inclusion and tier ordering; no gap found.
- `pkg/policymatch/zone_local_display_3358_test.go` — authored zone-local names in output; no qualified-name leak found.

Z6 differential ledger: exact/single-wildcard/both-any/global/scoped-global/default and junos-host ordering match the Rust oracle; strict selector validation and lenient content rejection remain fail closed; address books/sets/feeds, excluded addresses, application sets, protocol/ports and ICMP type/code cover IPv4/IPv6; scheduler state, stable IDs, descriptions, actions, queried scope, host-inbound tokens and route-drop notes are carried consistently across the shared result. Screens, interface filters, NAT, PBR, route lookup, sessions/flow cache, snapshot publication and HA are not evaluated by this policy-only function; callers correctly present it as `match-policies`, except that F1's missing non-first-fragment state makes its explicit claim of runtime semantic parity false for a security-critical packet class. No Z4 handoff finding: coarse host-inbound denies, fine junos-host denies, and global control accepts remain separately named/read.

### Scheduler

- `pkg/scheduler/scheduler.go` — local-time/date/day windows, wall-clock fail-close, callback retry and state locking; concurrent callback ordering candidate suppressed as duplicate `prior:ps-review-038.md`.
- `pkg/scheduler/scheduler_3849_test.go` — absent/partial/date-only window fail-close matrix; no new gap found.
- `pkg/scheduler/scheduler_localtz_3988_test.go` — local calendar boundary regression; no UTC drift found.
- `pkg/scheduler/scheduler_republish_3780_test.go` — failed publish retry/status behavior; no new issue beyond the duplicate race.
- `pkg/scheduler/scheduler_test.go` — daily/overnight/day override/date/update/clock discontinuity matrix; no new issue.


## A10-b5


Every assigned path was completed. “No new defect” entries state the substantive property checked, not merely that the file was opened.

| Path | Review result |
|---|---|
| `pkg/upgrade/cluster_cli.go` | No new defect: status parsing defaults false on missing/malformed peer, sync, RG, and protocol evidence; RG enumeration errors block drain. |
| `pkg/upgrade/cluster_cli_test.go` | No new defect: real formatter parity and malformed/partial status negatives cover peer readiness, sync, local primary, and configured RG extraction. |
| `pkg/upgrade/cutover.go` | Finding 1 caller: standalone cut uses the lossy cluster-marker boolean; other phase ordering, rollback, source-generation, and verify gates remain fail-closed. |
| `pkg/upgrade/cutover_cluster_gate_5284_test.go` | Coverage gap merged into Finding 1: present/absent marker cases exist, but no EACCES/EIO/symlink-target error case. |
| `pkg/upgrade/cutover_refuse_test.go` | No new defect: unsafe versions, unsanctioned first cuts, and pre-STOP refusal remain mutation-free. |
| `pkg/upgrade/flip.go` | No new defect: version/link/drop-in flips validate targets and preserve restart/rollback recovery ordering; no unbounded hot-path work. |
| `pkg/upgrade/helper_health.go` | No new defect: readiness requires active unit plus reachable enabled/armed helper whose `/proc` executable directory equals the target version. |
| `pkg/upgrade/helper_health_5286_test.go` | No new defect: helper-down, unarmed, stale-version, resolver failure, and timeout negatives prevent false commit. |
| `pkg/upgrade/imageversions.go` | No new defect: required unsigned-16 protocol fields and exact session-sync matching fail closed on absent, zero, malformed, or incompatible versions. |
| `pkg/upgrade/imageversions_test.go` | No new defect: compatible-window positives and missing/mismatch/unknown protocol negatives cover mixed-base verdict boundaries. |
| `pkg/upgrade/kernel.go` | No new defect: kernel state definitions and substrate interface keep package/version/boot-entry decisions explicit and bounded. |
| `pkg/upgrade/kernel_drain.go` | No new defect: peer alive, takeover-ready, protocol-compatible, drain, and rejoin predicates abort on errors/timeouts and fail back where possible. |
| `pkg/upgrade/kernel_drain_test.go` | No new defect: dead peer, incompatible protocol, not-ready peer, timeout, and observation-error cases exercise denial paths. |
| `pkg/upgrade/kernel_linux.go` | No new defect: package queries, boot-entry parsing, purge/install, hold assertions, mount handling, and command failures are surfaced; destructive paths validate segments. |
| `pkg/upgrade/kernel_linux_test.go` | No new defect: kernel package and boot-entry parser boundaries reject malformed command output and preserve expected package identity. |
| `pkg/upgrade/kernel_pkgquery_5428_test.go` | No new defect: dpkg-query output and host integration checks pin exact installed-package classification rather than substring admission. |
| `pkg/upgrade/kernel_purge_5076_test.go` | No new defect: failed purge does not delete package files or advance state. |
| `pkg/upgrade/kernel_run.go` | No new defect: candidate segments are validated before mutation; arm/promote/revert state transitions preserve known-good fallback and bounded attempts. |
| `pkg/upgrade/kernel_selfrecover.go` | No new defect: malformed/unknown lease state, armed trials, observation errors, and unhealthy peers suppress autonomous rejoin. |
| `pkg/upgrade/kernel_selfrecover_test.go` | No new defect: active, expired, malformed, other-node, armed, peer-unhealthy, and grace-reset lease cases cover false recovery. |
| `pkg/upgrade/kernel_test.go` | No new defect: arm/promote/revert happy and failure paths cover journal state, candidate identity, rollback, and cleanup guards. |
| `pkg/upgrade/kernel_version_validate_5452_test.go` | No new defect: unsafe candidate, package, and boot segments are rejected before command or filesystem mutation. |
| `pkg/upgrade/lock/lock.go` | No new defect: flock ownership spans metadata update and release; busy lock fails without truncating another owner’s active metadata. |
| `pkg/upgrade/lock/lock_test.go` | No new defect: contention, stale metadata, release, and truncation sequencing are covered. |
| `pkg/upgrade/lock_integration_test.go` | No new defect: upgrade and rolling callers hold/release one host lock across the entire mutating interval and on error. |
| `pkg/upgrade/lock_seam_test.go` | No new defect: test seam restores global lock acquisition and prevents cross-test leakage. |
| `pkg/upgrade/manifest/manifest.go` | No new defect: managed and lockstep binary lists are copied on return and remain a single bounded SSOT. |
| `pkg/upgrade/manifest/manifest_drift_test.go` | No new defect: packaging, staging, and maintainer-script binary lists are checked against the Go manifest. |
| `pkg/upgrade/preflight_dbsnap_failclosed_5074_test.go` | No new defect: DB EACCES/EIO/walk failures abort before snapshot/cut mutation; ENOENT alone permits the no-DB path. |
| `pkg/upgrade/read_journal_malformed_4876_test.go` | No new defect: malformed present journal returns error so staged-generation GC cannot discard unknown protection. |
| `pkg/upgrade/rolling.go` | No new defect: peer readiness and protocol compatibility precede demotion; lock spans drain through rejoin; transient waits are bounded. |
| `pkg/upgrade/rolling_test.go` | No new defect: dead/incompatible/unready peers, drain failback, transient sync, and timeout paths are negative-tested. |
| `pkg/upgrade/runner.go` | Finding 1 root: `ClusterNodeIDPresent` treats all `os.Stat` errors as absence; copy/journal durability and bounds review found no separate defect. |
| `pkg/upgrade/runner_test.go` | No new defect outside Finding 1: fresh cut, disk-full, verify rejection, rollback, crash resume, checksums, and deep fsync behavior pass. |
| `pkg/upgrade/runtime/seed.go` | No new defect: first-install seed validates versions, copies atomically, preserves modes, and refuses unsafe existing layout. |
| `pkg/upgrade/runtime/seed_test.go` | No new defect: first seed, idempotence, stale temp, unsafe version, non-directory, and mode-preservation cases pass. |
| `pkg/upgrade/stagedgen/fsutil.go` | No new defect: atomic symlink and durable file helpers constrain temp names and fsync parent directories. |
| `pkg/upgrade/stagedgen/stagedgen.go` | No new defect: generation IDs are validated; publication is immutable; GC protects current, journal-pinned, and retained generations. |
| `pkg/upgrade/stagedgen/stagedgen_test.go` | No new defect: publish, interrupted temp, current-link safety, retention, and protected-generation negatives pass. |
| `pkg/upgrade/stagedgen_cut_test.go` | No new defect: torn staging, superseded generations, same-version replacement, live-dir refusal, GC protection, and resume pinning are covered. |
| `pkg/upgrade/state.go` | No new defect: forward milestones and rollback sentinel ordering are explicit; unknown states do not compare as completed. |
| `pkg/upgrade/system_linux.go` | No new defect: binary-version output is parsed and validated; verify exit 3 remains a clean reject while other command failures surface. |
| `pkg/upgrade/system_linux_test.go` | No new defect: garbage, unsafe tokens, and execution failures cannot become version paths. |
| `pkg/upgrade/verify_cleanup_test.go` | No new defect: verify cleanup never deletes active/previous versions, persists rewind before snapshot removal, and fsyncs sweeps. |
| `pkg/upgrade/version.go` | No new defect: ASCII single-segment version and kernel tokens reject separators, dot aliases, whitespace, controls, and traversal. |
| `pkg/upgrade/version_test.go` | No new defect: accepted release forms and unsafe segment classes cover the path-safety contract. |
| `pkg/wgkey/wgkey.go` | No new defect: 32-byte key length, Curve25519 clamping, CSPRNG failure propagation, and encoding lengths are enforced. |
| `pkg/wgkey/wgkey_test.go` | No new defect: RFC vector, clamping, uniqueness, wrong length, and hex/base64 failures pass. |
| `scripts/deploy/test_xpf_deploy_correctness.py` | No new defect: backend argument construction, image identity, and day-0 correctness negatives pass. |
| `scripts/deploy/test_xpf_deploy_disk.py` | No new defect: golden-image copy/overlay and same-disk protections prevent artifact mutation and cross-VM sharing. |
| `scripts/deploy/test_xpf_deploy_gate.py` | No new defect: signature, manifest, hash, provenance, channel, HA mixed-base, and command-failure gates are negative-tested. |
| `scripts/deploy/test_xpf_deploy_image_roll_identity.py` | No new defect: post-recreate version and node identity mismatch blocks rejoin/second-node roll. |
| `scripts/deploy/test_xpf_deploy_iso_mode.py` | No new defect: generated secret-bearing ISO mode is asserted owner-only on success. Prior world-readable-ISO root was deduplicated. |
| `scripts/deploy/test_xpf_deploy_kernel_roll.py` | No new defect: arm failure, reboot boundary, and command return handling prevent false roll completion. |
| `scripts/deploy/test_xpf_deploy_lease_ttl.py` | No new defect: lease TTL parsing and hold behavior preserve half-roll exclusion. |
| `scripts/deploy/test_xpf_deploy_nicorder.py` | No new defect: positional management/data NIC order and physical-device forms reject zone-swapping layouts. |
| `scripts/deploy/test_xpf_deploy_pathsafety.py` | No new defect: instance, version, manifest, and remote path tokens reject separators and shell/path injection. |
| `scripts/deploy/test_xpf_deploy_robustness.py` | No new defect: preflight and cleanup failures surface stderr and avoid deleting unrelated resources. |
| `scripts/deploy/xpf-deploy.py` | No new defect after prior-root suppression: signatures/hashes precede install; HA roll leases and identity gates are bounded; cleanup is ownership-scoped. |
| `scripts/dist/publish.py` | No new defect after prior-root suppression: private snapshot closes publish TOCTOU; default-deny tree walk, provenance, signatures, latest pointers, and apt signer agreement gate upload. |
| `scripts/dist/sign.py` | No new defect: signing key/pubkey resolution rejects placeholders and verification is delegated to minisign with checked return codes. |
| `scripts/dist/test_publish_provenance.py` | No new defect: validated=false/missing/mismatched provenance blocks publish while signed validated provenance passes. |
| `scripts/dist/test_publish_snapshot.py` | No new defect: backend receives the gated private snapshot rather than a concurrently mutable source tree. |
| `scripts/image/bake.py` | No new defect after dedup: base SHA pin, validate-before-sign ordering, ownership-tag cleanup, and package/kernel gates were checked. |
| `scripts/image/make_config_drive.py` | No new defect after prior world-readable-output root suppression: config validation rejects invalid input and successful ISO output is chmod 0600. |
| `scripts/image/test_bake_base_pin.py` | No new defect: reviewed releases require pinned SHA and same-origin unpinned checksum remains explicitly non-publishable. |
| `scripts/image/test_bake_sign_ordering.py` | No new defect: failed/skipped validation cannot produce publish-accepted provenance and signing follows validation. |
| `scripts/image/test_make_config_drive_mode.py` | No new defect: output mode and node-id validation are covered. |
| `scripts/image/test_validate_ownership.py` | No new defect: cleanup refuses untagged or differently tagged Incus instances/images. |
| `scripts/image/test_validate_scenarios.py` | No new defect: required validation scenarios, QEMU structure, node identity, and failure verdicts are exercised. |
| `scripts/image/validate.py` | No new defect: scenario failures raise nonzero; ownership-scoped cleanup runs in `finally`; signature mode and boot probes are explicit. |
| `scripts/iperf-json-metrics.py` | No new defect after dedup of prior parser-integrity root: malformed/empty intervals fail and numeric metrics preserve bounded JSON processing. |
| `scripts/mtr_report_check.py` | No new defect after dedup of prior parser-integrity root: missing hops/samples and threshold violations produce failure, not an empty pass. |
| `scripts/test_mtr_report_check.py` | No new defect: malformed, empty, loss, latency, and valid report cases exercise result polarity. |
| `scripts/userspace_ha_validation_matrix_test.py` | No new defect: each matrix command checks return code and required output token across IPv4/IPv6/fallback cases. |
| `test/incus/cluster_status_parse.py` | No new defect: parser keys exact RG/node/state tuples and rejects incomplete status records. |
| `test/incus/cluster_status_parse_test.py` | No new defect: malformed, duplicate, transition, and stable ownership samples are covered. |
| `test/incus/cold-path-flooder/src/main.rs` | No new defect: packet/port arithmetic uses checked or widened bounds; thread count and affinity are bounded; FD ownership and shared fatal state are synchronized. |
| `test/incus/cos_be_contention_validate.py` | No new defect: missing/partial series, queue mismatch, throughput, latency, and fairness thresholds fail the verdict. |
| `test/incus/cos_be_contention_validate_test.py` | No new defect: positive and negative contention datasets cover all gate dimensions. |
| `test/incus/cos_port_grid_test.py` | No new defect: fixture port-to-class mapping is exhaustive and unknown ports fail rather than inherit a default rate. |
| `test/incus/fairness_cov.py` | No new defect: empty/zero/invalid samples are rejected and CoV computation is numerically bounded. |
| `test/incus/fairness_cov_test.py` | No new defect: equal, skewed, empty, and malformed samples cover calculation polarity. |
| `test/incus/fairness_equal_flow_capture.py` | No new defect: subprocess failures and absent interval evidence abort capture; process cleanup is bounded. |
| `test/incus/fairness_multi_sample.py` | No new defect: sample completeness, structural RSS expectations, throughput floors, and aggregate verdicts fail closed. |
| `test/incus/fairness_multi_sample_test.py` | No new defect: extensive malformed, partial, stale, timeout, RSS, CoV, and subprocess-failure cases pass. |
| `test/incus/fairness_surplus_giveback_validate.py` | No new defect: handback requires an observed transition and complete before/after evidence. |
| `test/incus/fairness_surplus_giveback_validate_test.py` | No new defect: no-transition, wrong owner, incomplete sample, and valid handback cases cover false pass. |
| `test/incus/iperf3_sum_parse.py` | No new defect: parser requires valid receiver SUM evidence and does not silently use partial stream rows. |
| `test/incus/iperf3_sum_parse_test.py` | No new defect: sender/receiver, malformed, absent SUM, and valid JSON cases pass. |
| `test/incus/mouse_latency_aggregate.py` | No new defect: invalid markers and missing cells poison aggregate verdict; p99 medians and threshold comparison are explicit. |
| `test/incus/mouse_latency_aggregate_test.py` | No new defect: invalid, incomplete, threshold fail, and pass matrices cover decision logic. |
| `test/incus/mouse_latency_orchestrate.py` | No new defect: child failures/timeouts create invalid markers, cleanup processes, and prevent aggregate PASS. |
| `test/incus/mouse_latency_orchestrate_test.py` | No new defect: command failure, timeout, marker propagation, and successful orchestration are covered. |
| `test/incus/mouse_latency_probe.py` | No new defect: histogram/sample validation, socket errors, and insufficient observations return nonzero. |
| `test/incus/mouse_latency_probe_test.py` | No new defect: malformed replies, timeout, sample floor, percentile, and valid probe cases pass. |
| `test/incus/policy_scheduler_validate.py` | No new defect: despite the name this validates CoS scheduler metrics, not security policy; unknown classes and incomplete counters fail. |
| `test/incus/policy_scheduler_validate_test.py` | No new defect: unknown scheduler, missing metrics, threshold fail, and valid scheduler cases cover verdict polarity. |
| `test/incus/retire_ebpf_artifact_schema.py` | No new defect: artifact scans use an explicit schema/allowlist and fail on retired dataplane residues. |
| `test/incus/retire_ebpf_artifact_schema_test.py` | No new defect: allowed userspace artifacts and forbidden eBPF names/paths/fields are differentiated. |
| `test/incus/step1-histogram-classify.py` | No new defect: histogram class evidence is schema-checked and missing/unknown slots cannot produce PASS. |
| `test/incus/step1-histogram-classify_test.py` | No new defect: malformed bins, missing coverage, threshold fail, and valid classifications pass. |
| `test/incus/step1-rate-spread-analysis.py` | No new defect: empty samples and invalid rates fail; spread arithmetic handles zero denominators. |
| `test/incus/step1-rss-multinomial.py` | No new defect: input counts and multinomial expectation bounds are validated before reporting. |
| `test/incus/step2-sched-switch-classify.py` | No new defect: trace completeness and switch classifications reject missing CPUs/events and malformed timestamps. |
| `test/incus/step2-sched-switch-classify_test.py` | No new defect: empty, partial, malformed, and valid scheduler traces cover the classifier. |
| `test/incus/step2-sched-switch-reduce.py` | No new defect: reducer requires complete per-CPU evidence and propagates invalid input to a failing verdict. |
| `test/incus/step2-sched-switch-reduce_test.py` | No new defect: duplicate/missing CPUs, bad intervals, empty data, and valid reduction cases pass. |
| `test/incus/step3-tx-kick-classify.py` | No new defect: kick evidence, counters, and time windows are validated; absent observations do not become success. |
| `test/incus/step3-tx-kick-classify_test.py` | No new defect: malformed, missing, threshold, and positive kick datasets cover polarity. |
| `test/incus/test_mouse_latency_shell_test.py` | No new defect: shell wrapper propagates probe/orchestrator failure rather than masking it. |
| `test/xsk-repro/libbpf_xsk_shared_test.c` | No new finding after prior AF_XDP reproducer-safety root suppression; shared-owner/secondary flags and zero-copy status are checked, but live-root execution remains diagnostic-only. |
| `test/xsk-repro/libbpf_xsk_test.c` | No new finding after prior reproducer-safety dedup; attach/bind/map/receive/link-cycle failures return nonzero. |
| `test/xsk-repro/main.rs` | No new finding after prior reproducer-safety dedup; build passes, result requires RX before/after cycle, and unsafe calls are confined to the diagnostic binary. |
| `test/xsk-repro/xdp_pass_redirect.c` | No new defect: map lookup gates redirect and missing queue entries pass to kernel as explicitly intended for this standalone diagnostic. |

## Cross-Layer Zone-Policy Review

| Lane | Cross-layer invariants | Non-source files | Raw candidates | Canonical lane-only roots | Acceptance |
|---|---|---:|---:|---:|---|
| Z1 | strict-lenient, policy-tiers, address-application-scope | 17 | 6 | 0 | tooling-v3 accepted |
| Z2 | typed-wire, compatibility, transactional-publication | 22 | 5 | 1 | tooling-v3 accepted |
| Z3 | shim-gates, tuple-order, special-paths, generated-replies | 59 | 6 | 1 | tooling-v3 accepted |
| Z4 | kernel-rust-order, coarse-fine-composition, host-exemptions | 9 | 4 | 3 | tooling-v3 accepted |
| Z5 | authorization-token, config-readiness, promotion-invalidation | 187 | 5 | 0 | tooling-v3 accepted |
| Z6 | differential-vectors, api-cli-output, diagnostic-parity | 29 | 7 | 0 | tooling-v3 accepted |
| Z7 | live-abi, compatibility-fields, retired-residue | 11 | 6 | 0 | tooling-v3 accepted |

The lanes trace authored policy through strict and tolerant compilation, typed publication, Rust snapshot admission, first-packet classification, session/cache reuse, generated replies, HA promotion, host-local kernel rules, and diagnostic surfaces. Raw lane findings were deliberately allowed to overlap source findings; the cross-adjudicator collapsed those overlaps before counting canonical roots.

One lane result is intentionally retained from a prior publication family as a material severity escalation. The source-batch ledger treated separate forwarding/CoS Arc publication as prior-owned; Z2 then proved that new validation can be observed with old forwarding and can stamp an old permit with the new generation, preserving it after convergence. That persistent firewall fail-open raises the prior Medium consistency root to a High security root and expands the immutable bundle/read-retry boundary to include validation.

## Validation Limitations

- The design review ended `DESIGN NO` for the audit harness attestation model, not for the packet/policy architecture: non-source handoff identity and required-new-test declarations are not cryptographically independent. Lane evidence is therefore supplementary source/test evidence, not formal certification.
- No stable live appliance matrix was available for every zone pair, HA fault, kernel/userspace crossover, malformed packet, and concurrency interleaving. Focused unit, overlay, race, and static probes were used; hardware/NIC scheduling and full failover behavior still require cluster validation before fixes ship.
- Early campaign scratch data was removed during worktree cleanup. Deterministic reports were recovered and rebound to the immutable base; cited source snippets and all 30 batch records were reauthenticated without changing finding bodies. This recovery reduces provenance assurance compared with an uninterrupted run and is disclosed explicitly.
- The report is a triage artifact. Medium- and Low-confidence items require issue-level reproduction before implementation, and all proposed fixes need their own adversarial review and regression tests.

## High Confidence Findings

### C180-001: Worker-visible validation and forwarding rotate as separate generations

Title: Worker-visible validation and forwarding rotate as separate generations

Severity: High

Confidence: High

Evidence: `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:228-232` creates new validation; lines `303-304` store validation and forwarding through separate ArcSwaps; line `331` rotates dependent CoS maps later. `userspace-dp/src/afxdp/worker/loop_body/mod.rs:364-372` loads validation and forwarding independently, with CoS loads at `503-550`. `userspace-dp/src/afxdp/flow_cache.rs:167-174` stamps cache lookup with the separately loaded validation generation. The static artifact pins these exact store/load orders.

Trace: After validation store but before forwarding store, a worker loads new validation and retains old forwarding. It can evaluate and cache an old permit with the new generation stamp. After forwarding rotates, generation equality no longer invalidates that cached decision. The inverse schedule, where old validation is loaded before both stores and new forwarding afterward, can retain an old-generation cached permit while newer policy is visible. Status already reports the incoming generation at the handler layer.

Refutation attempt: Build-first coordinator validation, ArcSwap pointer checks, session-remap purges, flow-cache generation checks, worker command ordering, #1188 design text, and existing refresh tests were reopened. Build-first prevents rejection-time mutation but does not make multiple stores one worker-visible commit. Generation checks are ineffective when an old decision is stamped with the new validation value. No reader retry compares a forwarding generation, because forwarding carries no common commit tag.

Final cross-adjudication: A successful refresh stores new validation before new forwarding. A worker can load the new validation, retain old forwarding, evaluate an old permit, and insert it with the new generation stamp; after forwarding rotates, equality validation preserves that stale permit beyond the transient publication window. This is a persistent policy fail-open with a distinct reader/writer coherence repair.

HPC/invariant check: Publish one immutable worker runtime bundle containing validation, forwarding, and generation-coupled references, loaded once per worker iteration. This can reduce independent Arc loads and adds no per-packet allocation or lock. Mutable counters/leases can remain behind references but their identity set must be bundle-consistent.

Why it matters: A new deny is not guaranteed to invalidate every stale permit at one coherent boundary; a transient publication window can create a cache entry that outlives the window while status honestly reports only the new generation.

Fix direction: Build a generation-tagged `WorkerRuntimeSnapshot` and perform one ArcSwap; pin one bundle for command drain and RX processing, and invalidate cache/session state on bundle identity change. Add deterministic barriers around writer stores and worker loads to prove old-or-new permit/deny behavior, plus a stress test that rejects mixed generation tuples.

Labels: snapshot-publication, worker-rotation, ArcSwap, generation, flow-cache, policy-invalidation, concurrency, fail-open

Dedup note: Related to prior `Successful snapshot refresh publishes forwarding before its CoS ownership and lease generation` and `Full snapshot generation rollback or reuse can preserve stale flow-cache permit decisions`. This lane records the concrete validation-before-forwarding/new-generation cache-stamp schedule and leaves final duplicate/merge disposition to the coordinator. Cross-adjudication: Hostile comparison reopened codex-review-161 H2, codex-review-177 A1-b10-F1, and codex-review-177 A1-b8-F4. They cover failed-build mutation, generation rollback/reuse, and forwarding-before-CoS respectively; none owns successful new-validation/old-forwarding cache stamping. Source was reopened at snapshot_refresh.rs:228-304, worker/loop_body/mod.rs:364-454, and flow_cache.rs:535-541/872-880.

### C180-002: Planned failover can promote a peer with stale security policy because session readiness has no applied-config epoch

Title: Planned failover can promote a peer with stale security policy because session readiness has no applied-config epoch

Severity: High

Confidence: High

Evidence: `pkg/cluster/sync_conn.go:287` resets session generation maps and, without any reboot proof or config payload, also clears the successfully-applied config high-water. The comment's claim that the next config is always current is not enforced by the bulk protocol.
```go
func (s *SessionSync) resetRecvGen() {
	s.recvGenMu.Lock()
	s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
	s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
	s.recvGenMu.Unlock()
	// #3931: also reset the last-applied config generation. A reconnecting
	// peer may have REBOOTED, restarting its monotonic configGenCounter at a
	// value LOWER than the generation we stored from its previous boot.
```
`pkg/cluster/sync.go:199` defines transfer readiness solely in terms of session bulk state; it carries neither the sender's current config generation nor the receiver's successfully applied generation.
```go
type TransferReadinessSnapshot struct {
	Connected             bool
	PendingBulkAckEpoch   uint64
	PendingBulkAckAge     time.Duration
	BulkReceiveInProgress bool
	BulkReceiveEpoch      uint64
	BulkReceiveSessions   int
}
```

Trace: Runtime trace command `go test ./pkg/cluster -run 'Test(ConfigSyncApplyFailureRetainsHighWater|ResetRecvGenResetsConfigGen|TransferReadinessReportsPendingBulkAckAndBulkReceive|ConfigSyncOrderedApplyDropsReorderedOlder)$' -count=1 -v` passed. It demonstrates three production semantics together: reordered generation 1 is rejected while high-water is 2; `resetRecvGen` then deliberately makes a lower generation admissible; a failed config apply leaves no applied high-water; and transfer readiness observes only bulk markers. Production trace: first packet is admitted on node A under policy/application/zone snapshot C2 and its session (PolicyID/counter/app timeout, but no config epoch) is synced to B. A restrictive C3 can fail/drop on B (`configApplyLoop` or full nonblocking queue) while session bulk/barriers settle. `computeUserspaceTransferReadiness` returns ready from connectivity plus those markers, then request/ack/commit promotes B. New packets and imported sessions are consequently evaluated/reused under stale C2, so traffic denied by C3 can forward; the inverse C3 permit can false-deny under stale C2. A routine `BulkStart` also clears B's C2/C3 ordering high-water and can admit an older reordered config.

Refutation attempt: I traced `RequestPeerFailover`, `ManualFailover`, batch variants, `prepareUserspaceRGDemotionWithTimeout`, `waitLocalFailoverCommitReady`, barriers, bulk ack, HA protocol mismatch, heartbeat health, config apply counters, policy-deletion/modified/default invalidation, session wire fields, and userspace helper import/promotion. Connectivity and protocol-version guards exist, and policy invalidation runs after a config actually applies. None proves that the target applied the source's current config. `ConfigsApplyFailed`/`Errors` are status-only. Session records carry `PolicyID`, `PolicyCounterIdx`, and `AppTimeout`, not an authoritative config generation. The barrier orders the session stream but does not acknowledge config application. Existing tests explicitly bless resetting the config high-water on a session bulk and never combine config failure/divergence with failover admission. Thus callers and validators do not refute the stale-policy takeover.

Final cross-adjudication: Retain the planned-failover admission root. A config can fail or be dropped before the standby publishes it, yet transfer readiness can still become true because it observes only session transport and bulk state. Audit-178 A6-b2-F1 instead assumes the newer config applied and addresses a delayed old-policy session imported afterward; adding an epoch to that session does not prove that an otherwise idle standby applied the authoritative config before promotion. The BulkStart reset is supporting evidence and should not become a second issue inside this canonical finding. Lane Z5-F001 and the independent High verification both confirm that session transport readiness lacks successful configuration-publication identity.

HPC/invariant check: No packet-hot-path allocation or lock is added by the diagnosis. The violated invariant is control-plane: promotion must require `peer_applied_config_epoch == local_authoritative_config_epoch` before synced sessions may become forwarding-authoritative. Current bounded queues and atomics keep runtime work bounded but do not establish that invariant. Any fix should use constant-size epoch fields/acks and avoid scanning sessions on the failover path.

Why it matters: This is both fail-open and false-deny. After a tightening commit, the promoted node can admit traffic the operator explicitly denied; after a loosening commit it can drop allowed traffic. Synced sessions may also be attributed to positional policy IDs/counters from a different snapshot, corrupting audit/show data. The failure is most likely exactly when HA is needed: apply degradation, reconnect, rapid commits, or cold sync.

Fix direction: Decouple session install generations from config generations. Give config sync a boot/session identity plus monotonic epoch, acknowledge only after `OnConfigReceived` successfully publishes the dataplane snapshot, expose local/peer applied epochs in transfer readiness, and block planned failover until they match the authoritative RG0 config. Do not clear config ordering on a session `BulkStart`; reset it only on authenticated sender-boot identity change. Retry the latest config after apply failure/queue pressure and add an end-to-end test for C2 applied, C3 failed/dropped, bulk settled, failover refused; also test reordered old config across BulkStart.

Labels: lane:Z5, security, fail-open, false-deny, ha, session-sync, policy-generation, snapshot-publication, v4-v6, tests

Dedup note: Searched the frozen dedup index for config generation, bulk reset, transfer readiness, policy rematch, session sync and failover. Prior #3931/#4151 fixes order apply and retain high-water on failure; #2198 F2 resets generations for peer reboot; #4034 pushes config after nonfatal local apply errors. None records the missing applied-config acknowledgment in failover readiness or the unsafe coupling of config high-water reset to session BulkStart. This finding merges those same-root symptoms. Cross-adjudication: Searched the full index and reopened audit-176 R6-b1-01 at line 479, audit-177 A5-b1-F10 and A8-b1-F2, and audit-178 A6-b2-F1 at line 6472. Those own false local apply acknowledgement, old queued config across peer boot, transport-specific omitted sync, and stale session import respectively. None owns the planned-transfer comparison peer_applied_config_epoch == authoritative_config_epoch, so the readiness mechanism and fix surface are materially distinct. The complete Z5 lane trace and independent-high-verification.md were checked against the source; they corroborate this applied-config convergence root and identify no prior final owning it. Corroborating inputs merged: lane:Z5-F001.

### C180-003: Standby config-sync tail failures permanently bypass policy session invalidation

Title: Standby config-sync tail failures permanently bypass policy session invalidation

Severity: High

Confidence: High

Evidence: `pkg/daemon/daemon_apply.go:347`
```go
	}
	if compiled != nil {
		if err := d.applyConfigLocked(d.applyCancelCtx(), compiled); err != nil {
			return nil, err
		}
		d.clearSessionsForDeletedPolicies(oldActive, compiled)
		d.clearSessionsForModifiedPolicies(oldActive, compiled)
		d.clearSessionsForDefaultPolicyChange(oldActive, compiled)
```

Trace: Primary commit promotes the tightened/deleted policy, applies the new snapshot, clears local sessions, and sends the config. The standby `SyncApply` also promotes the config and its dataplane snapshot can succeed, but a later best-effort tail failure such as host-inbound/lo0 nft or networkd makes `applyConfigLocked` return non-nil. `syncAndApply` returns before all three session invalidators. The callback reports failure, but the standby store already contains the incoming text; on the next peer re-push `handleConfigSync` takes its equal-active-text fast path and returns success without re-entering `syncAndApply`. A surviving established session therefore retains old authorization and is eligible to forward immediately after failover under the new policy.

Refutation attempt: I traced the primary path and the independent HA delete stream. `applyAndSyncCommitted` correctly classifies nonfatal tail errors and still clears/sends. `QueueDeleteV4/V6` journals deletes while disconnected, which often masks the standby bug. It does not refute the root: the journal is bounded and explicitly evicts old deletes, session enumeration/delete can be partial, and the local standby invalidation was intentionally added as a belt-and-suspenders guarantee. Config generation retry also does not repair it because store promotion happened before the tail error and the equal-text shortcut suppresses the retry. Required-protocol-gate and context-cancel errors are different: those disarm/stop the dataplane and may legitimately skip invalidation.

Final cross-adjudication: Retain the receive-side lifecycle defect. SyncApply promotes the new active tree before runtime reconciliation, but syncAndApply returns on any apply error before all three policy invalidators. A nonfatal tail failure therefore leaves an armed standby with old authorized sessions, and the equal-active-text fast path makes the omission permanent. The primary HA delete stream mitigates common cases but is bounded and does not replace the receiver's promised local invalidation before takeover. Lane Z5-F003 and the independent High verification confirm the promoted-store, nonfatal-tail, skipped-invalidation, equal-text-retry sequence.

HPC/invariant check: This is commit-frequency work, not packet hot path. The fix must retain `applySem` serialization and avoid a second full session scan when no policy/default/scheduler IDs changed. The key invariant is: once a config is promoted and the dataplane remains armed, nonfatal tail errors cannot skip authorization invalidation.

Why it matters: A deleted policy, tightened policy under `policy-rematch`, inactive scheduler, or default-policy permit-to-deny change can leave the standby forwarding a session that the primary has revoked. The defect becomes externally visible at failover, exactly when the standby assumes authorization ownership.

Fix direction: Make `syncAndApply` mirror `applyAndSyncCommitted`: capture `applyErr`, return early only for `applyErrSkipsPeerSync` fatal/stop classes, run all invalidators and passive admission checks for nonfatal tail errors, then return `compiled, applyErr`. Add a synced-standby test with a real old/new policy diff, injected nonfatal tail error, surviving v4/v6 sessions, and an equal-text retry assertion.

Labels: security, HA, sessions, policy-rematch, default-policy, runtime-ordering, fail-open, Z5

Dedup note: Distinct from closed #4034, which fixed the primary skipping config transmission on a nonfatal tail error, and from #4234/#4342/#4343, which added invalidators. This is the uncorrected receive-side analogue: promotion succeeds but those invalidators are skipped. No matching prior root was found in the frozen dedup index. Cross-adjudication: Searched the full frozen index and reopened #4034/PR #4039, #4234/PRs #4252 and #4320, and audit-178's configuration-epoch finding. #4034 owns sender-side transmission after a tail error; #4234 owns adding invalidation; audit-178 owns late session import. None owns a promoted receive-side config whose tail error skips invalidation and whose equal-text retry then no-ops. The Z5 lane, source report, codex-review-177 sender-side history, and independent verification were compared; none of the prior roots owns this receive-side permanent omission. Corroborating inputs merged: lane:Z5-F003.

### C180-004: A per-interface IKE or ident exception is widened to every interface in the zone

Title: A per-interface IKE or ident exception is widened to every interface in the zone

Severity: Medium

Confidence: High

Evidence: `pkg/config/junos_host_deny.go:371`, `pkg/config/junos_host_deny.go:861`, `pkg/daemon/daemon_nft.go:687`
```go
	for _, ov := range zc.InterfaceHostInbound {
		if ov != nil {
			add(ov.SystemServices)
		}
	}
	return out
}
```
```go
	if p.HasApplicationAnyDeny {
		if p.CoarseAdmitsIKE {
			// The coarse gate admits IKE (udp 500/4500) from any source, and the
			// userspace IPsec passthrough reinjects it before the fine policy, so
			// the fine drop must not swallow it.
			*rules = append(*rules, "    iifname "+iif+" udp dport { 500, 4500 } accept")
		}
```

Trace: `junosHostProjectProgram` computes one `CoarseAdmitsIKE` and one `CoarseIdentResets` bit for a whole zone. `zoneEffectiveSystemServices` obtains those bits by unioning every per-interface override, while the program's `IngressIfnames` contains every non-lifeline netdev in the zone. The daemon emits a terminal, destination-independent IKE accept or ident-reset rule across that full iifname set before the per-interface destination-scoped coarse rules. The overlay fixture gives `ge-0/0/1.0` an additive `ike` override and leaves sibling `ge-0/0/2.0` at zone-default `ping`; generated nft contains `iifname { "ge-0-0-1", "ge-0-0-2" } udp dport { 500, 4500 } accept` before `ip daddr 10.0.3.10 ... drop`. IKE is thus falsely allowed on the sibling. The same aggregate root can synthesize a TCP/113 reset on a sibling that should silently deny.

Refutation attempt: `BuildZoneHostInboundViews` itself correctly creates separate address/service views and the sibling coarse drop is present. That does not help because nft's earlier terminal exception ends this base chain before that drop. The global ESP/AH and reply-direction exceptions are intentionally global; this finding is limited to exceptions whose truth was derived from one effective interface set.

Final cross-adjudication: Valid per-interface IKE or ident admission is unioned into a zone-wide projection bit, then emitted as a terminal exception for every interface in the zone before interface-specific coarse drops. A least-privilege override can therefore admit or actively reset traffic on a sibling interface, requiring per-effective-view exception scopes.

HPC/invariant check: This is config-time projection and nft generation, not packet hot-path allocation. Correct output can group interfaces by identical effective exception bits, preserving one O(1) rule/set lookup per group.

Why it matters: A least-privilege interface override enlarges management-plane reachability on sibling interfaces without a matching config statement, deny counter, or tuple log. The generated rule contradicts the service matrix's additive per-interface scope.

Fix direction: Derive IKE and ident exception scopes per effective interface view, and emit each shield only for the corresponding iifname/address group. Include `ike`, `ipsec`, `all`, `any-service`, and `ident-reset` mixed-interface fixtures with both rule-order and packet-verdict oracles.

Labels: host-inbound, per-interface, IKE, IPsec, ident-reset, junos-host, nftables, false-allow, Z4, vsrx-parity

Dedup note: No matching root appears in the frozen dedup index. A3-b4's accepted mixed-case-token false deny occurs before projection; this finding uses valid normalized tokens and is a zone-scope false allow/generated-reply defect. Cross-adjudication: Searched every prior final for CoarseAdmitsIKE, zoneEffectiveSystemServices, per-interface IKE/ident exceptions, and sibling-interface admission. C179-045 covers mixed-case false denial before projection; no prior report owns this valid-token zone-scope false allow.

### C180-005: Kernel-established inbound host sessions retain authorization after coarse policy tightening

Title: Kernel-established inbound host sessions retain authorization after coarse policy tightening

Severity: Medium

Confidence: High

Evidence: `pkg/daemon/daemon_nft.go:619`, `pkg/daemon/daemon_nft.go:626`, `pkg/daemon/daemon_nft.go:303`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1149`
```go
		for _, p := range programs {
			emitJunosHostDenyProgram(&rules, p)
		}
		emitHostInboundICMPAccepts(&rules)
		rules = append(rules, "    ct state established,related accept")
	} else {
		rules = append(rules, "    ct state established,related accept")
		rules = append(rules, "    meta l4proto { 50, 51 } accept")
		emitHostInboundICMPAccepts(&rules)
	}
```
```rust
// #3070 + #3485: on the session-HIT local-delivery path,
// the host-inbound-traffic zone gate runs BEFORE the lo0
// host-bound filter. Re-checked on every hit (so a
// tightened host-inbound set tears down an already
// established host-bound session WITHOUT an explicit
// purge); the ingress zone is the session metadata's
// recorded ingress_zone. A host-inbound DENY is a silent
// drop with NO lo0 side-effects (no reject reply, no lo0
// counter/log) — before #3485 the lo0 filter ran first, so
// a denied service still triggered its reject/RST/teardown/
// counter/log (codex-review-118 M1). Only an ADMITTED
// packet pays the lo0 evaluation.
```

Trace: A direct kernel-local inbound flow admitted under an old host-inbound set creates a Linux conntrack entry. Replacing the `xpf_hostinbound` table does not flush conntrack. With no fine program, and for non-denied sources with one, the broad `ct state established,related accept` precedes every per-interface coarse drop, so subsequent original-direction packets retain old authorization and produce no host-inbound deny counter/log. Rust explicitly rechecks the current effective host-inbound set on every local-delivery session hit and tears down a denied session. The overlay `TestAuditZ4EstablishedPrecedesKernelCoarseGateTrace` renders a tightened empty coarse view and proves the stale established accept is earlier than its replacement drop.

Refutation attempt: Firewall-originated flow returns legitimately need the existing `ct direction reply` exception, and fine Junos-host denies can stop a matching source before the residual established accept. Neither refutes a remote-originated flow tightened only by the coarse service set. The Rust comment establishes revocation-on-tightening as the intended local-delivery contract.

Final cross-adjudication: The nft host-input chain accepts original-direction established conntrack entries before current per-interface coarse drops, and table replacement does not flush those entries. Removing a host service can therefore leave an existing direct-kernel connection authorized under the old configuration, unlike Rust's per-hit host-inbound recheck.

HPC/invariant check: Re-evaluating nft service matches for original-direction established packets is still kernel rule evaluation and requires no userspace packet allocation. Preserve the early reply-direction exception and global ICMP/IPsec controls.

Why it matters: A commit that removes SSH, HTTPS, SNMP, or another host service can report success while an existing direct-kernel connection continues under the old authorization. Equivalent userspace-local sessions are revoked, creating a false allow limited to one delivery path.

Fix direction: Keep `ct direction reply` before host-inbound, but require original-direction established packets to pass the current per-interface coarse rules before acceptance. Add a network-namespace test that establishes a host flow, tightens the service set without clearing conntrack, and verifies the next original-direction packet drops and increments `xpfhi_`.

Labels: host-inbound, conntrack, established, configuration, authorization, kernel, Rust, false-allow, Z4

Dedup note: No matching host-input conntrack root appears in the frozen index. Z5 session invalidation findings concern xpf userspace session tables and HA; this is Linux conntrack plus nft ordering on direct host delivery. Cross-adjudication: Searched all prior finals for host-inbound tightening, nft established/related ordering, Linux conntrack, and policy invalidation. Existing userspace-session invalidation roots and historical local-session gaps have different state owners; no prior final covers this kernel conntrack mechanism.

### C180-006: Unbuildable Time Exceeded and PTB attempts consume global reply tokens and can starve other interfaces

Title: Unbuildable Time Exceeded and PTB attempts consume global reply tokens and can starve other interfaces

Severity: Medium

Confidence: High

Evidence: `userspace-dp/src/afxdp/icmp.rs:184` consumes the process-global Time Exceeded token before looking up the ingress egress object or proving either family builder returns bytes:
```rust
// #2472: per-reason token-bucket rate limit on the LOCALLY-GENERATED Time
// Exceeded. A TTL=1 / hop-limit=1 flood (a routing loop or a crafted
// low-TTL stream) would otherwise emit one generated ICMP error per
// trigger packet, unbounded — a CPU/TX amplification + reflection sink.
// The bucket is global-per-reason (Linux `icmp_msgs_per_sec` model); on
// empty we drop the generated error and bump the observable
// `TimeExceeded` rate-limited counter (inside `allow_generated_error`).
if !allow_generated_error(GeneratedErrorReason::TimeExceeded) {
```
The PTB site has the same ordering at `userspace-dp/src/afxdp/tx/dispatch/mod.rs:230`: suppression passes, a token is consumed, and only then can `build_frag_needed_v4` / `build_packet_too_big_v6` return `None`.
```rust
if !ptb_reply_suppressed(source_frame, ptb_meta, l3, forwarding)
    && allow_generated_error(GeneratedErrorReason::PacketTooBig)
{
    ptb_reply = match meta.addr_family as i32 {
        libc::AF_INET => build_frag_needed_v4(
            source_frame,
            ptb_meta,
            ingress_ident.ifindex,
```

Trace: Runtime mechanics were exercised with `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::icmp_ratelimit`: the deterministic burst/refill tests show that every successful `allow_generated_error*` call advances the shared GCRA TAT and that denied calls do not refund it. Static call tracing then reaches fallible egress lookup/builders after that irreversible consume. Reproduction shape: configure one addressed interface A and one ingress/interface shape B for which the ICMP builder has no matching-family primary/egress; send more than the 1000-token burst of otherwise reply-eligible TTL=1 or oversized DF packets on B, then send a legitimate trigger on A within the refill window. A's generated error is suppressed by B's failed-build attempts.

Refutation attempt: The RFC suppression predicates do run before token consumption and reject malformed/group-source/error/fragment triggers, which narrows attacker inputs. They do not prove builder feasibility: Time Exceeded still performs `forwarding.egress.get` and family-specific builders after the bucket; PTB builders likewise require logical-interface egress/source-address/L2 data and return `Option`. The reject path demonstrates the intended guard by building first and consuming its token only after `Some(bytes)`; no refund API or caller retry restores TE/PTB tokens. The original packet remains correctly dropped, so this is not a forwarding fail-open and is not escalated to High.

Final cross-adjudication: The finding survives hostile refutation. Time Exceeded and Packet Too Big use process-global per-reason capacity, yet a reply-eligible packet can consume capacity before a missing egress object, missing family address, or fallible builder proves that any reply bytes exist. Failed work on one interface can therefore suppress buildable diagnostics on another interface without changing the correctly terminal disposition of the trigger packet. Cross-area review attaches the Time Exceeded/PTB portion of lane Z3-F003 here and does not collapse the separate output-filtered reject root.

HPC/invariant check: Packet work remains O(1), lock-free, and allocation-free in the bucket itself. The violated invariant is resource accounting: a scarce global token must correspond to a feasible generated frame. Because TE/PTB buckets are process-global rather than per-zone/interface, failed work on one interface creates cross-interface false denial. Reordering build before consume adds cold-path builder work only for reply candidates and matches the existing reject implementation; it does not add hot-path locks or scans.

Why it matters: An attacker able to deliver low-TTL or oversized traffic on an interface where reply construction fails can suppress PMTUD and traceroute/TTL diagnostics for unrelated legitimate traffic. PTB starvation can sustain blackholes for flows that depend on PMTUD, while the rate-limited counters misleadingly attribute suppression to excess generated replies even though no frame was buildable.

Fix direction: Build the TE/PTB frame first as a side-effect-free feasibility step, then consume the reason token only for `Some(bytes)`, then classify/enqueue. Alternatively add an explicit reservation/refund primitive, but build-before-consume already exists for policy/filter reject and is simpler. Add cross-interface tests that drain failed builders and assert a legitimate builder still receives the full burst; assert counters move only for genuinely rate-limited feasible replies.

Labels: generated-control, ICMP, IPv4, IPv6, PMTUD, resource-accounting, false-deny, DoS, Z3-handoff, tests

Dedup note: Searched the immutable dedup index for Time Exceeded/PTB token, bucket, feasibility, unbuildable, and rate-limit ordering. Existing #2237 covers RFC suppression, #2238 generated-tuple output classification, #2472 missing rate limiting, and #3656 build-before-consume only for reject. This TE/PTB consume-before-fallible-build root is distinct. Cross-adjudication: Searched the complete frozen dedup-index for Time Exceeded, PTB, generated-error buckets, feasibility, unbuildable replies, and token-before-build. The closest root is #3656, which moved only policy/filter reject construction before its different per-zone reject bucket; #2237, #2238, and #2472 cover suppression, classification, and adding the limiter, not this ordering. Lane Z3-F003 was compared against both campaign token findings; only its failed-build TE/PTB mechanism merges here, while source:A1-b2-F002 remains independently canonical. Corroborating inputs merged: lane:Z3-F003.

### C180-007: Filter, policy, host-inbound, and embedded-ICMP classifiers can read L4 semantics from Ethernet slack

Title: Filter, policy, host-inbound, and embedded-ICMP classifiers can read L4 semantics from Ethernet slack

Severity: Medium

Confidence: High

Evidence: `userspace-dp/src/afxdp/frame/inspect.rs:606` determines ICMP byte availability from the physical frame length, even though the IP-declared end is only computed later at line 635. The same function derives fragment state from `frame[l3..]` at lines 591-597 rather than a declared-length-bounded slice. Authentic frozen source:
```rust
    let icmp_type_code_present = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !non_first_fragment
        && (frame.len() >= (meta.l4_offset as usize).saturating_add(2));
    let l4_truncated = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !non_first_fragment
        && !icmp_type_code_present;
```

Trace: Send an Ethernet-minimum IPv4 frame whose header says protocol ICMP and `total_length=20` (no declared ICMP bytes), while bytes at the shim-stamped `l4_offset` in Ethernet padding are `8,0`. `term_match_extra_from_frame` sees `frame.len() >= l4+2`, sets `l4_present=true`, and returns echo-request. `policy_packet_icmp` (`poll_descriptor/mod.rs:126-134`) passes that fabricated type/code to application matching; input/lo0 filter calls at `poll_descriptor/mod.rs:1712-1718` and `2202-2226` consume the same values; host-inbound separately reads the same physical byte at `poll_descriptor/mod.rs:2216-2219`. A terminal permit constrained to echo-request can therefore match a packet whose declared IP datagram contains no ICMP header, while a terminal deny can false-drop it. For IPv6, a payload length of zero plus padding beginning with a fragment header similarly makes `is_fragment` true. `icmp_embed/parse.rs:45-87,180-205` also bounds quoted L4 reads by the outer backing slice instead of the quoted IP declaration, allowing padding to manufacture an existing-session tuple.

Refutation attempt: I opened the XDP metadata consumers, policy ICMP helper, input/PBR/lo0 evaluators, flowless path, host-inbound gate, embedded session lookup, the declared-length helpers at `inspect.rs:1056-1117`, and the #5150 tests. Metadata is explicitly documented at `inspect.rs:1315-1319` as not guaranteeing L4 lies within the IP-declared datagram. The #5150 change clamps only `flex_l3`/`flex_l4`; its tiny-length regression at `frame/tests.rs:7510-7536` does not assert `l4_present`, ICMP bytes, or fragment state. No downstream validator removes the fabricated scalar match before policy/filter evaluation. The forwarded malformed packet may be rejected by a final host, which limits payload impact, but the firewall decision, counters/logs, session lookup/touch, and active-reply behavior have already been driven by out-of-datagram bytes.

Final cross-adjudication: The declared-length defect remains on scalar security inputs even though flexible byte slices were fixed. ICMP type/code presence, TCP flags, fragment state, and l4_present can be derived from physically present Ethernet slack and can influence policy, filter, host-inbound, counters, or session matching. The embedded-ICMP parser has the same authority error for a quoted inner datagram, so this is a live security-classification surface rather than a restatement of the repaired flex slice. Lane Z3-F002 independently reproduces the same declared-length authority error and therefore corroborates this canonical rather than adding another issue.

HPC/invariant check: The fix should reuse the already computed `declared_end` and slice once; it adds no allocation or lock and removes reads, preserving bounded eight-header IPv6 work. The invariant should be: every scalar L4/fragment/filter/policy input is derived only from `[l3, declared_end)`, never the Ethernet backing length.

Why it matters: Security rules and host-control admission are expected to fail closed on malformed/truncated packets. Physical padding is attacker-influenced on received frames and must not turn a non-match into a permit, manufacture fragment status, touch an established session, or produce misleading policy/filter counters and logs.

Fix direction: Compute the family-aware declared end before any fragment/L4 extraction; pass `frame.get(l3..declared_end)` to fragment walkers; require `l4+2 <= declared_end` for ICMP and `l4` plus the relevant TCP bytes for TCP flags; set `l4_present=false` otherwise. Apply the same declared-inner-bound validation to embedded IPv4/IPv6 quote parsers without rejecting legitimate RFC-minimum quotes whose original declared length exceeds the available quote. Add IPv4/IPv6 tests with short declared lengths plus physical slack for ICMP type/code, TCP flags, first/non-first fragment, host-inbound, Junos application policy, input/lo0 filters, and embedded-session lookup.

Labels: zone-policy, fail-open, false-deny, parsing, IPv4, IPv6, fragments, host-inbound, firewall-filter, session

Dedup note: The prior-root index and frozen history contain #2361 (declared-length port reads), #2449 (physically truncated ICMP), and #5150 (flexible-match slack clamp). This is the residual scalar-match/fragment/embedded-session surface left outside those fixes, not a duplicate of their fixed loci. Cross-adjudication: Full-corpus searches for declared length, Ethernet slack, l4_present, ICMP type, TCP flags, fragments, and embedded quotes found #2361 (live ports), #2449 (physical truncation), and audit-177 M3/#5150 (flex slices). Those roots repair different consumers; none covers these residual scalar and embedded-session consumers. The complete Z3 lane trace was compared with this source record and with the prior #5150 flexible-slice repair; it has the same remaining scalar and embedded-quote fix boundary as this input. Corroborating inputs merged: lane:Z3-F002.

### C180-008: Egress-filtered reject replies drain the per-zone reject bucket before being discarded

Title: Egress-filtered reject replies drain the per-zone reject bucket before being discarded

Severity: Medium

Confidence: High

Evidence: `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:325` consumes the zone token at line 330, while generated-reply output classification does not occur until line 374 and can return a drop at lines 375-392. Authentic frozen source:
```rust
    let from_zone_id = forwarding
        .ifindex_to_zone_id
        .get(&logical_ingress_ifindex)
        .copied()
        .unwrap_or(0);
    if !allow_generated_reject(forwarding, from_zone_id) {
        counters.touched = true;
        // #3661: attribute the rate-limit drop to the reply's SOURCE so a
```

Trace: In one ingress zone, configure policy/filter reject for unwanted traffic and an output filter that discards generated ICMP but permits TCP RST. Flood rejected UDP/ICMP queries. Each trigger builds a valid ICMP unreachable, passes the TX budget, consumes `allow_generated_reject`, then `classify_generated_reply` returns `drop` and no reply is enqueued. The flood exhausts that zone's shared reject bucket. A subsequent rejected TCP SYN, whose RST would pass the output filter, fails at line 330 and silently drops. Policy and filter rejects share the bucket by design, so either source can starve the other inside the zone.

Refutation attempt: I opened both policy/filter callers, `classify_generated_reply`, per-zone bucket construction/fallback, all reject tests, and commit history for #2238, #2472, #2955, #3615, #3618, #3656, and #3661. #3656 deliberately moved unbuildable frames before token consumption, establishing the anti-starvation invariant, but stopped before output classification. `reject_reply_dropped_by_egress_output_filter` and `filter_reject_output_filter_drop_uses_filter_counter` prove the terminal drop but neither snapshots/drains the bucket to ensure no token was spent. Per-zone buckets prevent cross-zone starvation only; they do not prevent this same-zone, cross-protocol/source starvation. The behavior survives without malformed packets and with ordinary supported filters.

Final cross-adjudication: The later-stage starvation mechanism is real and distinct from unbuildable reject replies. A buildable generated reject passes the TX budget and irreversibly consumes the shared per-zone token before output-filter or policer classification can discard it. Traffic whose generated ICMP is intentionally filtered can therefore exhaust the same-zone bucket and suppress a later TCP RST that the output filter would permit. The output-filter half of lane Z3-F003 corroborates this path, but the lane row is attached to its closest TE/PTB feasibility root so these different buckets and commit points remain separate canonicals.

HPC/invariant check: Generated reply classification is already paid on this cold reject path. Moving or splitting the pure terminal filter viability check before token consumption does not affect transit hot paths. Because classification may update policers/counters, do not naively duplicate it; either separate a side-effect-free terminal viability pass, classify once before the token with documented policer semantics, or add a correct token refund primitive.

Why it matters: An attacker can turn replies the operator intentionally suppresses into a token-exhaustion channel that downgrades unrelated, output-permitted active rejects to silent drops. This reduces observability and changes configured reject behavior exactly when the zone is under hostile traffic.

Fix direction: Ensure a reply discarded by generated-reply output classification does not consume the per-zone reject token. Preserve one classification and truthful source-split counters. Add a regression that records available bucket capacity, drives repeated output-filter drops, then proves an output-permitted RST can still consume the original capacity; cover policy and filter reject sources and VLAN logical-zone resolution.

Labels: zone-policy, reject, output-filter, rate-limit, availability, counters, IPv4, IPv6

Dedup note: The prior-root index/history fixes unbuildable-reply starvation (#3656), source attribution (#3615/#3661), and cross-zone starvation (#3618). No prior entry found covers output-filter-dropped but buildable replies consuming the token; this is the remaining later-stage feasibility case. Cross-adjudication: Searched the full index for generated reject, output filter, policer, bucket, token, and rate-limit ordering. #3656 is construction feasibility, #3618 is cross-zone isolation, and #3615/#3661 are truthful source-split accounting. None owns the output-filtered-but-buildable consume path, so it must not be merged with A1-b1-F001 or those prior roots. Cross-area comparison rejected Z3-F003's proposed collapse: this per-zone, buildable-reject/output-filter mechanism remains distinct from source:A1-b1-F001's process-global pre-build TE/PTB mechanism.

### C180-009: Policy counter clear accepts trailing selectors but still clears every policy

Title: Policy counter clear accepts trailing selectors but still clears every policy

Severity: Medium

Confidence: High

Evidence: `cmd/cli/clear.go:192` recognizes only the first two tokens and never requires exact arity before issuing the global action.
```go
	case "policies":
		if len(args) >= 2 && args[1] == "hit-count" {
			resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
				Action: "clear-policy-counters",
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
```

Trace: An overlay-only runtime test against the frozen package called `handleClearSecurity([]string{"policies", "hit-count", "from-zone", "trust"})`. Output was `err=<nil> actions=[clear-policy-counters]`. The production route is `dispatchOperational` -> `handleClear` -> `handleClearSecurity`; the server handles `clear-policy-counters` by calling `s.dp.ClearPolicyCounters()` with no zone/policy selector (`pkg/grpcapi/server_diag_system_action.go:136-143`). Thus the apparently scoped trailing input is discarded and all policy counters are reset.

Refutation attempt: I checked for downstream parsing or server-side selector recovery; `SystemActionRequest` carries only the literal action and the server performs the global clear. The sibling session-clear and DHCP-clear parsers explicitly reject unknown/trailing selectors before mutation, so permissive trailing syntax is not a general intentional contract. A bare exact `clear security policies hit-count` remains the intended global operation.

Final cross-adjudication: Both policy-counter clear clients accept ignored trailing operands and then invoke an unscoped global mutation. Selector-looking text therefore returns success while erasing all policy evidence, a distinct destructive-command parser failure rather than a counter-reset race. Lane Z6-F005 independently exercises both clients and merges into this destructive-command parser root.

HPC/invariant check: This does not change packet admission and adds no hot-path work, locks, allocations, or unbounded state. It violates the command/API fail-closed invariant: malformed mutating input must be rejected before RPC, especially when discarded words look like a scope and the only backend action is global. The clear implementation’s counter generation/race semantics are outside this parser finding and are separately covered by closed `#3448/#3782`.

Why it matters: During incident response an operator can type a policy or zone qualifier believing the clear is scoped, receive success, and erase every policy hit counter. That destroys the evidence used to determine which zone/global/default rules admitted or denied traffic and can invalidate before/after policy-change measurements.

Fix direction: Require `len(args) == 2` for the current global command and return a usage error for every trailing token. If scoped clearing is desired, add a typed RPC with explicit selectors rather than accepting words the backend cannot represent. Add a fake-client regression test asserting malformed/trailing forms issue zero `SystemAction` calls and the exact two-token form issues one global clear.

Labels: cli, policy, counters, destructive-command, fail-closed, observability, api-contract

Dedup note: No matching parser root was found in `dedup-index.txt`. Closed `#3448` and `#3782` concern races inside an already-authorized global clear, not acceptance of malformed/trailing CLI operands. The DHCP/failover/upgrade leftover-argument fixes are analogous precedents but different command handlers and side effects. Cross-adjudication: Searched the full index for policy hit-count, clear-policy-counters, trailing selectors/operands, and global clear. #3448/#3782 cover reset concurrency; audit 177 covers a different session-clear parser and different erased state, so neither owns this policy-counter surface. Z6-F005 was compared with policy-counter reset races and scoped session-clear parsers; it shares this exact ignored-trailing-operands/global-clear boundary. Corroborating inputs merged: lane:Z6-F005.

### C180-010: DDNS ownership state is read without a size bound before validation

Title: DDNS ownership state is read without a size bound before validation

Severity: Medium

Confidence: High

Evidence: `pkg/ddns/state.go:358` reads an attacker/corruption-sized file into memory in one operation before JSON, version, record-count, or semantic validation:
```go
func loadDDNSState(path string) (*ddnsState, error) {
    s := &ddnsState{path: path, records: map[string]ownedRecord{}}
    data, err := os.ReadFile(path)
    if err != nil {
        if errors.Is(err, os.ErrNotExist) {
            return s, nil
        }
        return s, fmt.Errorf("read ddns state %s: %w", path, err)
```

Trace: An overlay-only runtime test created a 16 MiB malformed state file and called the real unexported `loadDDNSState`; `go test -overlay=/tmp/a10_b3_overlay.json ./pkg/ddns -run TestA10B3StateLoadAllocationTrace -count=1 -v` logged `input_bytes=16777216 total_alloc_delta=16795080` before the loader returned its expected parse error. The production constructor reaches this loader through `loadStateOrDegrade`/manager initialization, so a sufficiently large durable file consumes input-proportional heap before the fail-closed corruption posture can engage.

Refutation attempt: The canonical file is mode 0600 and normally generated from bounded active configuration/lease state, so an unprivileged remote caller cannot directly upload arbitrary bytes. I checked `state.save`, durable writes, semantic validation, quarantine, and degraded-marker handling; none caps file bytes before `os.ReadFile`. A prior crash, filesystem corruption, administrative restore, or future producer defect can therefore leave a very large canonical file, and restart is exactly when the daemon must parse it. The 16 MiB trace rules out an argument that JSON rejection happens before input-sized allocation.

Final cross-adjudication: The ownership loader allocates in proportion to the entire durable file before any JSON, version, record, or semantic rejection can enter the degraded posture. Mode 0600 limits direct attackers, but corruption, restore, or producer failure can still obstruct daemon recovery through GC pressure or OOM. Lane Z6-F006 provides allocation measurements for the same pre-validation ReadFile path and merges here.

HPC/invariant check: This is cold startup/reconcile state, not the AF_XDP packet path, and introduces no cache-line or packet-latency issue. The resource invariant is violated: malformed persisted input must have a fixed byte/record ceiling before allocation. Fail-closed DNS ownership semantics remain correct after a bounded rejection; the process availability bound does not.

Why it matters: A large or corrupted ownership file can drive proportional heap growth, GC pressure, or OOM during daemon startup, preventing firewall control-plane recovery before the code can mark DDNS degraded. This is an operational denial, not unintended traffic admission.

Fix direction: Open/stat the file and reject sizes above a documented ownership-state maximum before allocation, then decode through an `io.LimitedReader` with an extra sentinel byte to close growth races. Also cap record count and per-string sizes during decode/semantic validation, classify over-limit as corrupt, and preserve the existing durable degraded/quarantine behavior. Add tests at limit, limit+1, and excessive record count without allocating the full claimed input.

Labels: resource-bounds, availability, ddns, persisted-state, fail-closed, CWE-770, lane-Z6

Dedup note: No matching root appears in the frozen dedup index. Prior DDNS reviews mention bounded HTTP/feed bodies and semantic state validation, but not the pre-validation `os.ReadFile` allocation of the ownership store; this is distinct from those roots. Cross-adjudication: Searched the full index for DDNS ownership/state size, ReadFile, allocation, persisted-state bounds, and record limits. Prior #2650/#2971 and audit 175 roots cover fail-closed parsing and semantic validity after reading, not the pre-validation memory bound. Z6-F006 was compared with prior semantic-validation and quarantine findings; its evidence strengthens but does not alter this pre-validation byte-bound root. Corroborating inputs merged: lane:Z6-F006.

### C180-011: Policy simulator cannot represent non-first fragments and reports permit where the dataplane applies the fragment-associated deny

Title: Policy simulator cannot represent non-first fragments and reports permit where the dataplane applies the fragment-associated deny

Severity: Medium

Confidence: High

Evidence: `pkg/policymatch/policymatch.go:234` exposes only zones, addresses, protocol, and ports; there is no `l4_present`, fragment offset, or non-first-fragment discriminator:
```go
type Query struct {
	FromZone string
	ToZone   string
	SrcIP    net.IP
	DstIP    net.IP
	Protocol string // "tcp", "udp", "89", "ospf", ... ("" = unspecified)
	SrcPort  int
	DstPort  int
```
`pkg/policymatch/policymatch.go:1596` then treats the zero ports that are the only available representation of a non-first TCP/UDP fragment as a simple application miss:
```go
	// The old `&& dstPort > 0` gate skipped the check entirely for an omitted
	// port, reporting a permit for a port-constrained app no concrete packet
	// would hit (sibling of #3323's protocol omission). An UNCONSTRAINED dst
	// port term (app.DestinationPort == "") still matches any port, unchanged.
	if app.DestinationPort != "" {
		if dstPort <= 0 || !portMatches(app.DestinationPort, dstPort) {
			return false
		}
	}
```

Trace: Executed `cargo test --manifest-path userspace-dp/Cargo.toml flowless_fragment_fails_closed_against_skipped_port_bearing_deny_4569 -- --nocapture`; the targeted Rust test passed one test. Its fixture is an earlier source-scoped `deny junos-https` followed by `permit any`: TCP/443 denies, ordinary TCP/80 permits, an overlapping non-first fragment (`l4_present=false`, ports 0) denies via the #4569 override, and a non-overlapping fragment permits. Executed all `pkg/policymatch` tests as part of the package suite; `TestPortConstrainedAppOmittedQueryPortNoMatch` confirms the Go side maps port 0 to a miss. In the same ordered deny-then-permit fixture, `Match` has no fragment bit, skips the deny at `dstPort <= 0`, continues its first-match loop, and returns the later permit. The same mismatch applies to IPv4 and IPv6 non-first fragments because the missing query dimension is family-independent.

Refutation attempt: Checked the selector grammar, `SelectorArgs`, protobuf request/callers, `ruleMatches`, `matchApp`, host path, and assigned tests for any hidden fragment/L4-presence input or caller-side override; none exists. Checked whether #4569 merely changed an internal drop unrelated to policy identity: the Rust regression attributes the denial to policy ID 7 and explicitly proves the later permit is overridden only for an overlapping flowless fragment. Checked dedup for `#4569`, `fragment-association`, `flowless fragment`, `simulator`, `match-policies`, and `test policy`; the dataplane fix is indexed, but this management-parity root is not. The issue is not refuted by omitting ports: that is exactly how the Go simulator represents unknown L4 today, while the runtime distinguishes ordinary unknown/other-port traffic from non-first fragments.

Final cross-adjudication: The shared simulator promises runtime precedence and semantics but cannot carry the L4-presence state that changes the live verdict for non-first fragments. In the deny-then-permit vector it skips the port-bearing deny and reports permit while Rust applies and attributes the #4569 fragment-associated deny. Lane Z6-F001 reproduces the non-first-fragment differential and merges into this management-schema parity root.

HPC/invariant check: The fix belongs entirely on the management cold path and must not alter the Rust hot path. Preserve bounded first-match work and the #4569 invariant: only a non-first/flowless fragment overlapping an earlier L3-matching port-bearing deny may override a later permit/default-permit; ordinary L4-present packets on other ports and non-overlapping fragments must remain permitted. Carry fragment state through CLI, REST, gRPC, and text bridges without allocation or locking in packet processing.

Why it matters: An operator can ask the shared policy oracle about the only tuple it can supply for a non-first TCP/UDP fragment and receive `permit`, while the live firewall drops that packet under a specific deny policy. This breaks the tool's stated semantic-parity contract, hides the enforcing policy ID, and can send incident response toward routing/screens instead of the actual security rule. A naive opposite fix that treats every zero-port query as a fragment would false-deny ordinary omitted-port simulations, so the missing discriminator must be explicit.

Fix direction: Add an explicit packet shape to `Query` and every selector/REST/gRPC/text transport, at minimum `non-first-fragment` or `l4-present`. Port the Rust #4569 skipped-overlapping-deny tracking into the simulator's exact, wildcard, global, default, and junos-host walks, preserving policy attribution. Add a paired matrix for IPv4/IPv6: first fragment denied port, ordinary different-port permit, overlapping non-first fragment deny, non-overlapping non-first fragment permit, plus output parity on CLI/REST/gRPC.

Labels: Z6-primary, policy-simulator, management-parity, fail-open-diagnostic, false-deny-avoidance, fragments, IPv4, IPv6, applications, CLI, REST, gRPC, tests, vsrx-parity

Dedup note: New root. The dedup index contains the dataplane fix `git:24b50500e policy: fail closed a non-first fragment that skips a port-bearing DENY (#4569)` and prior reviews of Rust flowless behavior, but no simulator/request-schema parity finding. Scheduler callback ordering was separately suppressed as duplicate `prior:ps-review-038.md`. Cross-adjudication: Searched the full index for #4569, fragment association, flowless/non-first fragment, simulator, match-policies, l4_present, and management parity. git:24b50500e owns dataplane enforcement; no prior root owns the missing management request dimension or opposite diagnostic verdict. Z6-F001's paired Go/Rust vector was compared with #4569's enforcement fix and this source; the missing request dimension and simulator remedy are identical. Corroborating inputs merged: lane:Z6-F001.

### C180-012: Cluster marker I/O errors bypass both standalone-cut HA safety gates

Title: Cluster marker I/O errors bypass both standalone-cut HA safety gates

Severity: Medium

Confidence: High

Evidence: The exported predicate in `pkg/upgrade/runner.go:199` maps every `os.Stat` error, including permission and storage errors, to `false`:
```go
func ClusterNodeIDPresent(path string) bool {
if path == "" {
path = DefaultNodeIDFile
}
_, err := os.Stat(path)
return err == nil
}
```

Trace: Runtime reproduction at the frozen HEAD created an existing `node-id` below a mode-000 directory and invoked the exported production predicate from a temporary Go program. The trace was: `os.Stat error=stat /tmp/a10-nodegate.HulHir/node-id: permission denied` followed by `ClusterNodeIDPresent=false`. Source tracing then confirmed `cmd/xpfd/upgrade.go:67` and the final privileged boundary `pkg/upgrade/cutover.go:167` both branch only when this boolean is true. With false, execution continues through lock, preflight, verify, and ultimately the uncoordinated stop path.

Refutation attempt: I checked for a second authoritative HA classification after this predicate, for validation of the node-id contents, and for peer/RG readiness before `StopUnit` in the standalone path. There is none: comments at `pkg/upgrade/cutover.go:158` explicitly state the standalone flow has no peer/RG ownership transfer or readiness fence, and `ClusterCoordinated` is false for the bare CLI and documented recovery callers. The CLI “belt-and-suspenders” check is not independent because it calls the same lossy predicate. Running as root reduces ordinary DAC failures but does not refute EIO, ESTALE, read-only/mount faults, symlink-target failures, LSM denial, or injected/system-call errors. Existing `cutover_cluster_gate_5284_test.go` covers only clean present and clean absent states, so no test closes this branch.

Final cross-adjudication: The final HA guard still fails open when cluster identity is unknown: both checks reuse a boolean that maps every Stat error to standalone absence. Root execution reduces ordinary DAC failures, but EIO, ESTALE, LSM denial, and mount faults can still authorize an uncoordinated stop with outage impact. Independent hostile verification narrows reachability to persistent node-id-specific lookup failures because broad /etc/xpf faults are stopped by the config-DB preflight; the root remains real but warrants Medium impact.

HPC/invariant check: This is a cold-path availability and fail-closed invariant violation, not a hot-path performance issue. It adds no packet-path allocation/lock cost. The relevant invariant is “unknown cluster identity must never authorize a standalone stop”; only explicit `os.IsNotExist(err)` can establish standalone absence. The current collapse of unknown into absent permits unintended denial/blackholing of traffic, while changing it to tri-state error handling preserves bounded O(1) work.

Why it matters: `/etc/xpf/node-id` presence is the sole install-stable signal that the node is HA-managed. If its lookup fails transiently or because of storage/mount damage, a bare `xpfd upgrade` can stop the active node without first proving the peer owns every RG. The code’s own threat statement says this can blackhole traffic when the peer is not ready, defeating the #5284 final privileged guard exactly when local state is unreliable.

Fix direction: Replace the boolean API with `(present bool, err error)` or a three-state classifier. Return absent only for `os.IsNotExist`; propagate every other error. Make both the CLI and `Runner.Run` refuse before lock/journal/live mutation on unknown identity, with an error naming the failed path. Add injectable-stat or filesystem tests for EACCES/EIO and a dangling/unresolvable symlink, asserting no stop/start/drop-in/journal/current-link mutation; retain clean present, clean ENOENT, and coordinated-rolling cases.

Labels: upgrade, HA, fail-open, availability, operational-safety, test-gap

Dedup note: The dedup index contains commits `d7ad03537` / `ba9679990` for #5284’s intended present-marker gate, but no prior review root for collapsing non-ENOENT marker lookup errors into standalone absence. This is a residual error-classification bypass in the final guard, not a restatement of the already-fixed “no cluster gate” root. Prior publish, config-drive, performance-parser, and XSK reproducer roots were suppressed in the ledger. Cross-adjudication: Searched the full index for cluster marker, node-id, standalone cut, error classification, EACCES/EIO, audit 178, and #5284. Audit 178 and git:d7ad03537 own the missing-gate root; this is a distinct residual mechanism in the added gate's error classification. independent-high-verification.md was reopened and its full-cut preflight analysis was applied; it changes severity, not prior-root identity.

### C180-013: Conflicting scalar leaves in a direct application silently keep only the last condition

Title: Conflicting scalar leaves in a direct application silently keep only the last condition

Severity: Medium

Confidence: High

Evidence: `pkg/config/compiler_applications.go:61` assigns each direct scalar straight into the same field while iterating sibling leaves, without the value-aware duplicate tracking used for inline terms:
```go
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "protocol":
				app.Protocol = nodeVal(prop)
				hasDirectBody = true
			case "destination-port":
				app.DestinationPort = resolveAppPort(nodeVal(prop))
```

Trace: A temporary external Go harness parsed hierarchical input containing one direct application with `protocol tcp; protocol udp; destination-port 22; destination-port 53;`, then a zone-pair deny referencing that application and `default-policy permit-all`. `NewParser.Parse` returned zero errors, `SchemaValidate` returned nil, and strict `CompileConfig` returned nil with zero warnings. The typed application was `protocol="udp" destination_port="53"`. `policymatch.Match` reported `tcp/22` as the unmatched default permit (`action=0`, empty policy) while `udp/53` matched `block-dup` deny (`action=1`). This exercises parser, schema, strict compiler, typed config, application matching, policy terminal action, and default policy.

Refutation attempt: Duplicate authored application objects are rejected by `validateApplicationNameCollisionsAST`, but this input has one object with repeated child leaves. `validateApplicationStructureStrict` checks mixed direct-plus-term definitions and `DuplicateTermLeaves` generated only by `parseApplicationTerms`; it has no direct-body duplicate marker. Schema validation accepts repeated scalar siblings. Port/protocol semantic validation sees only the surviving valid `udp/53` values, so neither strict nor lenient gates can recover the discarded `tcp/22` pair. The same overwrite pattern applies to direct source-port, timeout/inactivity-timeout, icmp-type, icmp-code, and ALG fields; those symptoms are merged into this root.

Final cross-adjudication: Conflicting direct-body scalar siblings are overwritten before any duplicate evidence is recorded, so strict commit can accept only the final protocol, port, timeout, ICMP, or ALG value. That can under-match a deny and fall through to a permit/default permit. This direct-loop mechanism is separate from duplicate leaves inside an opaque term. Lane Z1-F001 reproduces the same direct-application scalar overwrite and merges into this source root.

HPC/invariant check: This is cold-path compilation. Tracking the first direct scalar value is O(number of leaves), bounded by config size, with no packet-path allocation, lock, or cache impact. Invariant: a single-valued direct application leaf may repeat idempotently, but conflicting values must reject strict commit and must never silently discard an earlier protocol, port, ICMP, timeout, or ALG condition. Lenient handling should retain an invalid-content marker so a malformed deny cannot under-match or a malformed permit change semantics.

Why it matters: Hierarchical load/override input that repeats a direct application leaf commits cleanly but enforces only the last values. A deny can cover fewer protocol/port combinations than authored and fall through to a permit/default permit, while a permit can be unintentionally narrowed. This violates compiler/vSRX parity and the requirement that ordinary configured permit/deny application and port conditions survive compilation.

Fix direction: Add value-aware direct-scalar tracking in `compileApplications`, parallel to the existing inline-term tracking. Record conflicting repeats on the typed application (including the timeout aliases as one field), reject them in `validateApplicationStructureStrict`, and preserve idempotent same-value repeats. For lenient load/HA, attach an unrepresentable-content marker or reject publication/retain last good rather than selecting one value. Add hierarchical parser plus `SchemaValidate`/`CompileConfig` tests for every direct scalar, and an end-to-end deny/default-permit test proving the discarded protocol/port cannot be admitted.

Labels: compiler, applications, protocol, ports, icmp, ALG, strict-commit, lenient-load, HA-sync, fail-open, false-deny, default-policy, tests, vsrx-parity

Dedup note: The dedup corpus contains closed #3366 for conflicting scalar leaves inside inline `term` and #3339/#3472 for duplicate application object/name collisions. This is the distinct direct-body sibling mechanism: `compileApplications` overwrites fields before either guard can observe the conflict. No dedup entry records a direct scalar duplicate fix; all direct field symptoms share this one root. Cross-adjudication: Searched the full dedup index and all root-level prior audit reports for direct-body duplicate/scalar terms. Closest #3366 covers mixed direct-plus-term storage and conflicting scalars inside term only; #3339/#3472 cover name collisions, and #2545 covers firewall-filter scalar modeling. None owns repeated direct application leaves. Z1-F001 was compared field by field with the source trace; protocol, ports, ICMP, timeout, and ALG are variants of this one direct-body value-aware duplicate-check boundary. Corroborating inputs merged: lane:Z1-F001.

### C180-014: Lenient policy compilation publishes missing or discarded constraints as wildcard permits

Title: Lenient policy compilation publishes missing or discarded constraints as wildcard permits

Severity: Medium

Confidence: High

Evidence: `pkg/config/compiler_policy_missing_match_3044_test.go:158` demonstrates that a permit lacking destination and application criteria is expected to compile successfully on the tolerant path:
```go
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a policy missing match criteria: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
```

Trace: Runtime harness through exported `ParseSetCommand`, `ConfigTree.SetPath`, and `CompileConfigLenient` printed `action=0 src=["any"] dst=[] apps=[] warnings=1`; `PolicyPermit` is enum value 0. `go test ./pkg/config -run 'TestPolicy(MissingMatchLenientDowngradesToWarning|MatchUnsupportedLeafLenientWarns|CompleteMatchCommits)$' -count=1 -v` passed. Downstream `expandUserspacePolicyApplications` returns `(nil, true)` for an empty slice, so no `__unsupported__` sentinel is emitted and the policy snapshot treats the absent application constraint as match-any. The same loss occurs when `validatePolicyMatchLeavesStrict` warns leniently after the compiler drops an unsupported AST leaf, and when an unsupported `then permit` modifier is warned but discarded.

Refutation attempt: Strict commit is not affected: the AST gates reject missing dimensions, unsupported leaves, and permit modifiers. I traced undefined non-empty applications/addresses and undefined zones into the userspace snapshot builders; those do receive an unrepresentable sentinel or snapshot-integrity rejection and retain last-good/default-deny. I also checked actionless policy handling, which explicitly rewrites to deny on lenient compile. None of those guards can distinguish this case because the missing/dropped AST information is absent from `Policy` after compilation, warnings are not consumed by snapshot lowering, and the existing tests assert warning presence only. Thus this is not refuted by callers, validators, compatibility paths, or tests.

Final cross-adjudication: The tolerant path deliberately downgrades missing-match, unsupported-match, and unsupported permit-service AST errors to warnings, but compilePolicy discards the invalid evidence. Empty application/address dimensions then remain legitimate wildcards, so the snapshot cannot quarantine the malformed permit. These symptoms share one missing invalid-policy marker root and can widen HA/persisted policy enforcement. Lane Z1-F002 reproduces the same tolerant-invalidity loss and wildcard-permit publication and merges here.

HPC/invariant check: This is cold-path config/snapshot work, not packet hot path. A fix should add O(number of policies) metadata during compilation and a constant-time per-rule sentinel check during snapshot build; it must not add packet-path allocation, locking, or cache lookups. Invariant: any malformed/unsupported lenient permit must compile to a never-match/quarantined rule or reject the candidate snapshot, never to an empty match dimension.

Why it matters: `CompileConfigLenient` serves persisted load and peer-sync compatibility. A legacy or HA-synced permit missing destination/application, carrying an unsupported match criterion, or relying on an unsupported permit service can become broader than configured and admit traffic that strict commit would reject. Warning-only behavior does not protect forwarding and violates the campaign requirement that lenient/HA compatibility must not widen permits.

Fix direction: Preserve per-policy invalid-content metadata while running lenient AST gates, keyed by stable scope/name or attached directly to the typed policy. During userspace lowering, turn that policy into the established unrepresentable-content sentinel (or reject the whole candidate snapshot while retaining last good). Keep daemon boot/no-brick behavior, but make forwarding fail closed. Add tests that inspect typed fields and built snapshots for zone-pair and global permits across missing match, unsupported match leaf, and unsupported `then permit`; include deny cases to avoid turning a malformed deny into an unintended broader default-policy permit.

Labels: zone-policy, compiler, lenient-load, HA-sync, fail-open, permit-widening, applications, scoped-global, tests

Dedup note: Adjacent historical roots `#3044`, `#3113`, and `#3114` fixed strict commit and intentionally documented warning-and-compile compatibility. The dedup index records those strict gates and the retained match-any behavior, but no entry records a quarantine/snapshot fix for the tolerant policy itself. This finding is limited to that still-live shared compatibility root and merges all three symptoms rather than re-reporting their strict-validation bugs. Cross-adjudication: Full-index and prior-report searches found #3044, #3113, and #3114 as the closest roots, but those own strict rejection and explicitly leave warning-and-compile compatibility. No prior root adds tolerant-policy invalid-content metadata or snapshot quarantine; this residual mechanism and publication boundary are distinct from those fixed strict gates. Z1-F002's missing/discarded constraint cases all reach the same empty typed fields and require the same retained-invalidity or quarantine fix as this source canonical. Corroborating inputs merged: lane:Z1-F002.

### C180-015: Route-filter validator accepts a match keyword in the CIDR slot and commits a match-none policy

Title: Route-filter validator accepts a match keyword in the CIDR slot and commits a match-none policy

Severity: Medium

Confidence: High

Evidence: `pkg/config/schema_validators_routing.go:82`
```go
// Known limitation: the validator is position-agnostic (the walker does
// not tell it which slot a token came from), so a match-type keyword in
// the prefix slot (e.g. `route-filter longer exact`) is accepted. This
// is strictly better than the pre-#2105 state (any garbage committed)
// and catches the real malformed-CIDR case; per-position validation
// would require schema restructuring and is deferred.
func ValidateRouteFilterArg(raw string, _ *Config) error {
```

Trace: `go run /tmp/repro_a3b5.go` built the real flat-set AST for `set policy-options policy-statement P term T from route-filter longer exact`, then printed `schema=<nil>`, `compile=<nil>`, and `prefix="longer" match="exact" action="accept"`. The FRR renderer's malformed-prefix belt calls `net.ParseCIDR("longer")`, emits no prefix-list entry, but retains the match against the undefined list so the term is NOMATCH. Thus a strict-accepted route import/export term that says accept is operationally deny.

Refutation attempt: Checked `validateRouteFilterMatchTypesStrict` and the FRR renderer. The semantic gate validates `MatchType=="exact"` but does not revalidate `Prefix`; the render belt intentionally skips malformed prefixes to fail closed. Existing schema tests reject malformed CIDRs only when the token is not also in the match-type set, so they do not refute the swapped-slot reproduction.

Final cross-adjudication: The current defect is positional category confusion, not the pre-#2105 absence of validation: one args:2 key validator accepts the union of CIDRs and match keywords in either slot. A keyword in the prefix slot therefore commits, while the renderer deliberately emits no list entry plus an undefined-list match, turning an authored accept term into NOMATCH. The residual requires slot-aware schema validation. Lane Z1-F005 reproduces the same swapped-slot route-filter validation and merges here.

HPC/invariant check: Validation and rendering are control-plane-only and linear in configured route filters. A positional validator adds constant work and no packet-path allocation or locking. The fail-closed renderer belt should remain for lenient/legacy state, while strict commit must reject the malformed slot before publication.

Why it matters: An operator can commit a syntactically invalid route-filter and receive success, but all routes expected to match that accepting term are denied. On BGP import/export or redistribution this can withdraw reachability or suppress advertisements with no commit-time explanation.

Fix direction: Give route-filter prefix and match-type distinct schema nodes/validators, or pass the key-slot index to a positional key validator. Require slot 1 to parse as CIDR and slot 2 to be a supported match type. Add flat and hierarchical swapped-slot tests plus strict-reject/lenient-match-none coverage.

Labels: config, routing, schema-walker, frr, false-deny, strict-lenient

Dedup note: The frozen dedup index contains route-filter rendering and malformed-prefix fixes but no finding for the documented position-agnostic `longer exact` acceptance root. Cross-adjudication: The full index's closest root is #2105/PR #2110, which fixed a node with no validator and FRR-garbage emission for arbitrary malformed CIDRs. I reopened that issue and prior reviews: the present union-validator slot confusion is explicitly deferred, has a different validator mechanism and slot-aware fix, and now fails closed as match-none rather than producing the old reload-invalid line. Z1-F005 was checked against the source record and prior malformed-prefix renderer work; both campaign inputs share the position-agnostic validator and prefix-slot repair boundary. Corroborating inputs merged: lane:Z1-F005.

### C180-016: Zone collision quarantine drops a multi-zone deny from surviving scope members

Title: Zone collision quarantine drops a multi-zone deny from surviving scope members

Severity: Medium

Confidence: High

Evidence: `pkg/dataplane/userspace/zones_quarantine.go:109` treats any quarantined name anywhere in the plural scope as a reason to reject the whole policy rather than removing only that member:
```go
refsQuarantinedZone := func(p PolicyRuleSnapshot) bool {
// #4626 M03: a scoped global's match-zone context is now a zone SET
// carried in the plural MatchFromZones/MatchToZones (singular kept for
// back-compat). Check EVERY element so a global scoped to a
// quarantined zone anywhere in its set is dropped, not just its first.
zones := []string{p.FromZone, p.ToZone, p.MatchFromZone, p.MatchToZone}
zones = append(zones, p.MatchFromZones...)
zones = append(zones, p.MatchToZones...)
for _, z := range zones {
```

Trace: `go test -overlay=/tmp/review-work-codex-180/runtime/a6_b3_overlay.json ./pkg/dataplane/userspace -run TestAuditA6B3MultiZoneDenyQuarantineTrace -count=1 -v` constructed a production `ConfigSnapshot` with colliding `z174`/`z214`, published `untrust`, and a global deny scoped from `[z174,z214]` to `[untrust]`. Production `quarantineCollidingZones` logged the `z214` collision, retained zones `[z174,untrust]`, and returned `policies=[]`. Therefore packets from surviving `z174` no longer encounter the configured deny and can reach a later/default permit.

Refutation attempt: I checked strict validation, lenient/HA rationale, Rust dangling-zone preflight, policy action handling, collision tests, and the original `git:84cbcb4c7` fix. Strict local commit rejects collisions, but the function explicitly exists for persisted, lenient, and old-peer states. Keeping the rule unchanged would brick publication, but that does not justify dropping its still-representable members. Unzoning `z214` makes that member irrelevant; it does not make traffic from retained `z174` irrelevant. Existing tests use singular scopes only and never test a deny with both quarantined and surviving members.

Final cross-adjudication: The plural quarantine over-drop is a distinct live mechanism. Collision handling keeps z174 and removes z214, so a global deny scoped from both zones remains fully representable for surviving z174. Instead, finding any quarantined member drops the entire rule, removing the deny from valid traffic and allowing a later/default permit. The old singular dangling-reference fix had to drop a one-member rule; it did not authorize discarding independently valid members added by the later plural model. Lanes Z2-F005 and Z7-F004 independently exercise the same partial plural-scope quarantine over-drop and merge here.

HPC/invariant check: The scrub runs once during snapshot build, so filtering two small zone slices adds no packet-path allocation or locking. The violated invariants are action-agnostic fail-closed lowering and preservation of global policy order/coverage for representable surviving zones.

Why it matters: A crafted or previously persisted StableZoneID collision can remove a deny from unrelated, still-valid zone members while the snapshot publishes successfully. The alarm reports quarantine, but forwarding is already broader than the remaining zone/policy model implies.

Fix direction: For scoped globals, subtract quarantined names from plural from/to sets, regenerate singular compatibility fields from the retained set, and drop the rule only when a configured side has no members left. If safe old-helper projection cannot be guaranteed, combine this with the capability gate from A6B3-01. Add deny/permit tests for first, middle, and last colliding members and a Rust preflight/evaluation test for the scrubbed snapshot.

Labels: security-policy, zone-identity, collision-quarantine, scoped-global, lenient-load, HA, fail-open, snapshot-lowering

Dedup note: Related to but not duplicated by `git:84cbcb4c7`, which fixed a dangling singular scoped-global reference by dropping the rule. This finding is the new plural-set over-drop introduced by extending that remedy to “anywhere in its set”; the retained-member fail-open is not in the dedup index. Cross-adjudication: Searched the complete index and prior reports for quarantine, StableZoneID collision, plural scoped globals, partial member survival, and policy over-drop. The closest entry is commit 84cbcb4c7 at line 1313, which fixes a singular dangling scope by dropping that rule; audit-179 C179-087 is old-helper projection, not current-helper collision scrub. Audit-179's negative quarantine ledger contains no retained root for partial plural preservation. Both lane traces were compared with this source and C179-087; they share this current-helper collision scrub boundary, not the separate old-helper singular projection root. Corroborating inputs merged: lane:Z2-F005, lane:Z7-F004.

### C180-017: Policy invalidation failures are logged but the commit still succeeds with stale authorized sessions

Title: Policy invalidation failures are logged but the commit still succeeds with stale authorized sessions

Severity: Medium

Confidence: High

Evidence: `pkg/daemon/daemon_policy_invalidate.go:283`
```go
	if v4EnumErr != nil || v6EnumErr != nil {
		slog.Error("policy session invalidation: session-table enumerate failed; clear is PARTIAL — some sessions of changed policies may keep forwarding",
			"change", what, "reason", reason, "policies", len(ids),
			"v4_err", v4EnumErr, "v6_err", v6EnumErr,
			"v4_matched", len(v4Entries), "v6_matched", len(v6Entries))
		// Fall through to clear what we DID enumerate — a partial clear is
		// strictly better than none — but the error log above ensures the
		// partial state is visible and the success line below is skipped.
```

Trace: A commit promotes and applies a policy deletion/tightening, then calls `clearSessionsForPolicyIDs`. A partial `ForEachV4/V6` error leaves unvisited sessions in the live table. A `DeleteBatchKnownV4/V6` error similarly leaves some or all matched sessions installed. The helper returns `void`; callers cannot join the error into the commit result, retry it, or mark the dataplane unready. The new policy governs session misses, but stale session hits continue using their old authorization until timeout, while the operator receives a successful commit response unless separately monitoring logs.

Refutation attempt: The code clears entries gathered before an iterator error and logs at Error, and HA delete propagation can clear a peer copy. Those are useful mitigations but do not clear unvisited local entries or make a failed local batch delete converge. Existing tests deliberately assert only that the partial state is logged and that gathered entries are attempted; they do not provide retry or fail the commit. Snapshot publication alone is not a guard, because #4234 introduced explicit session deletion precisely to revoke established-session authorization.

Final cross-adjudication: Retain separately from skipped invalidation: here invalidation is entered and partially attempted, but iterator or batch-delete failures are reduced to logs and the void helper gives commit, sync, and rollback callers no error, retry debt, or readiness signal. Gathered entries may be cleared, yet unvisited or unsuccessfully deleted sessions retain prior authorization. That is a distinct enforcement failure from #4234's former absence of invalidation and from A7-b1-F001's pre-call return. Lane Z5-F005 corroborates the attempted-but-failed invalidation mechanism and merges here.

HPC/invariant check: The scan is already off hot path and only runs when the ID set is non-empty. Returning an aggregated error adds no packet allocation or locking. A retry should remain bounded and avoid holding unrelated runtime locks; preserving companion-aware batch deletion and generation-ordered HA deletes is mandatory.

Why it matters: Tightening or deleting a policy can report success while packets in an established flow continue to forward. This violates the fail-closed commit contract and makes enforcement depend on session-table backend health and log monitoring.

Fix direction: Return an error from `clearSessionsForPolicyIDs` and its three wrappers, aggregate enumerate and batch-delete errors, and join them into commit/sync/rollback results after attempting every family. Add injected v4/v6 iterator and delete failures asserting a non-nil commit result plus a bounded retry/health signal; queue HA deletes only with explicit accounting of local delete outcome.

Labels: security, sessions, policy-invalidation, error-propagation, fail-open, IPv4, IPv6, Z5

Dedup note: Related to the Copilot #4320 observability follow-up, which suppressed a false success log on partial enumeration. That change did not propagate failure or repair stale authorization; this finding is the remaining enforcement/root-contract gap, not the documented policy-ID-0 compatibility exception. Cross-adjudication: Searched the complete index for policy invalidation enumeration, batch-delete, partial clear, retry, and commit error propagation. #4234 and PR #4320 are closest: they added the clear and corrected a false success log, respectively, but neither propagates or repairs a failed clear. No prior final report owns attempted-but-failed policy invalidation as a commit-contract root. Z5-F005 was compared with #4234 and #4320 as well as the source; void error handling, absent repair debt, and readiness impact are the same campaign root. Corroborating inputs merged: lane:Z5-F005.

### C180-018: Match-policies folds mixed per-interface host-inbound posture into an unqualified zone-wide admission

Title: Match-policies folds mixed per-interface host-inbound posture into an unqualified zone-wide admission

Severity: Medium

Confidence: High

Evidence: The assigned REST grammar has no ingress-interface selector (`pkg/api/security.go:526`), while its shared classifier iterates every effective host-inbound view in the queried zone and returns on the first admitting view (`pkg/dataplane/userspace/host_inbound_classify.go:156`). The response therefore cannot distinguish an interface that owns an SSH override from a sibling interface that remains default-deny.
```go
// matchPoliciesSelectorKeys is the exact, ordered set of query-string
// selectors the match-policies handler consults. It is the SINGLE source of
// truth for BOTH the #3709 duplicate-scalar check AND the #5316 unknown-key
// allowlist: a selector is added here (and only here), and both the reads and
// the two validation passes derive from it, so a new dimension cannot be
// duplicate-checked-but-not-allowlisted (or vice versa) and a caller typo can
// never silently re-open the fail-open gap.
var matchPoliciesSelectorKeys = []string{
	"from_zone", "to_zone", "src_ip", "dst_ip",
	"src_port", "dst_port", "protocol", "icmp_type", "icmp_code",
}
```
```go
for _, v := range views {
	for _, fam := range fams {
		if tok, kind, ok := hostInboundViewAdmit(v, proto, dstPort, icmpType, fam); ok {
			return HostInboundAdmission{Status: HostInboundTokenAdmit, Token: tok, Kind: kind}
		}
	}
}
// The zone is configured (post-#3405 every configured zone enforces) and
// nothing admits — default-deny.
return HostInboundAdmission{Status: HostInboundDenied}
```

Trace: A read-only `/tmp/a8_b1_trace.go` harness constructed a normal typed config with two `trust` units: only `ge-0/0/0.0` had `host-inbound-traffic system-services ssh`; `ge-0/0/1.0` had no override and therefore default-denied host-bound SSH. It also configured a normal `trust -> junos-host` permit policy. Running `go run /tmp/a8_b1_trace.go` from the frozen worktree produced:
```text
ge-0/0/0.0 effective=[ssh] ge-0/0/1.0 effective=[]
zone-only classification="token-admit" token="ssh"; matched=true policy_action="permit"
```
The first line uses the same effective union helper as interface diagnostics and proves the sibling postures differ. The second line exercises the classifier consumed by `matchPoliciesHandler`: because any zone view admits, the REST backing result reports an unqualified SSH admission and permit even though a packet entering `ge-0/0/1.0` is denied by normal configured semantics.

Refutation attempt: I checked whether the request or response carried an interface/address-to-view discriminator elsewhere. The complete allowlist in `matchPoliciesSelectorKeys` has no interface key; `policymatch.Query` receives only zones and tuple fields; `MatchPoliciesHostInbound` contains status/token/kind/description but no interface or ambiguity bit. Supplying `dst_ip` does not refute the root: `ClassifyHostInbound` derives only address family from the query and `hostInboundViewAdmit` does not constrain by the view's `V4Addrs`/`V6Addrs`. Existing REST tests cover zone-only service sets and an inventory containing one override, but never query a mixed zone and assert each sibling's opposite outcome. The behavior is not a duplicate of #3627/#4352, which added the structured token, nor #3646, which corrected unmatched-host wording; this is the distinct missing ingress-interface dimension introduced by per-interface overrides.

Final cross-adjudication: Retain the mixed-interface diagnostic aggregation defect. Runtime enforcement selects the effective host-inbound view by actual ingress interface, but match-policies has no interface dimension and ClassifyHostInbound existentially admits when any same-zone view admits. In a mixed zone the returned token-admit and matching permit are therefore unqualified and false for default-deny sibling interfaces. This changes query semantics and is not the earlier omission of a host-inbound token from an output transport. Lane Z6-F002 reproduces the mixed-interface existential fold and merges here.

HPC/invariant check: The endpoint is management-plane cold path; the issue does not alter packet forwarding, memory ownership, locking, or hot-path allocation. Current classification is bounded by configured host-inbound view/token count. A fix should preserve bounded work: accept and strictly validate one logical ingress interface, resolve its authoritative zone, and classify one effective view; alternatively return an explicit `ambiguous` result with bounded per-interface details when mixed views exist. It must not silently choose the first view or continue using existential-any semantics as a packet verdict.

Why it matters: Operators and automation use match-policies to certify whether a concrete host-bound tuple is allowed. In a common mixed zone, an SSH exception on one management-facing unit causes the API to report `token-admit` for the entire zone, including sibling units where the runtime correctly default-denies SSH. Combined with a matching host policy, the same response says `matched=true` and `action=permit`, creating a false admission diagnosis and potentially validating an exposure that does not exist or obscuring why connectivity is denied.

Fix direction: Add a canonical `ingress_interface` selector to REST, gRPC, and CLI match-policies queries, reject unknown/malformed/zone-mismatched refs, and classify `ZoneConfig.InterfaceHostInboundEffective(ref)` (including physical-to-unit inheritance and lifeline semantics) for that interface. For backward compatibility, a zone-only query should return `indeterminate`/`ambiguous` whenever effective interface views differ, and should include the differing interface groups rather than OR them. Add REST/shared-matcher tests with two addressed units in one zone, one SSH override and one default-deny, covering unmatched and matched junos-host policies.

Labels: api, match-policies, security-zone, host-inbound, per-interface, false-admission-diagnostic, vsrx-parity, tests

Dedup note: Searched the frozen v3 dedup index for match-policies plus interface/per-interface host-inbound admission. Related closed roots #3627/#4352/#4364 concern exporting the structured token, #3646 concerns unmatched-host wording, and #3362 concerns enforcing/inventorying overrides. None tracks the zone-wide existential fold or missing interface selector; this is a new root. Cross-adjudication: Searched the full index and reopened avo-review-001 F6, #3627 with PRs #4352/#4364, #3362, #3654, #3671, and #3710. Avo F6 and #3627 own missing token export; the other issues own enforcement or inventory views. None owns match-policies' zone-only existential fold across contradictory effective interface views, so the mechanism and affected API contract are distinct. Z6-F002's executable mixed-zone fixture was compared with prior host-inbound token-export and enforcement findings; it is corroboration of this missing query discriminator, not a second issue. Corroborating inputs merged: lane:Z6-F002.

### C180-019: Eligible REST policy hit counters become authoritative-looking zeroes when the dataplane is unloaded

Title: Eligible REST policy hit counters become authoritative-looking zeroes when the dataplane is unloaded

Severity: Medium

Confidence: High

Evidence: The assigned response contract always serializes both hit fields (`pkg/api/types.go:195`) with no availability or presence discriminator, even though `Count` says this rule is independently counter-enabled. The supporting handler constructs its reader only when the dataplane is loaded (`pkg/api/security.go:154`) and otherwise returns the completed inventory as HTTP 200 without reading or marking counters unavailable.
```go
	Description  string   `json:"description,omitempty"`
	Action       string   `json:"action"`
	SrcAddresses []string `json:"src_addresses"`
	DstAddresses []string `json:"dst_addresses"`
	Applications []string `json:"applications"`
	Log          bool     `json:"log"`
	Count        bool     `json:"count"`
	HitPackets   uint64   `json:"hit_packets"`
	HitBytes     uint64   `json:"hit_bytes"`
```
```go
	var readPolicy func(uint32) (dataplane.CounterValue, error)
	if s.dp != nil && s.dp.IsLoaded() {
		readPolicy = dpuserspace.NewPolicyCounterReader(s.dp, cfg, s.dp.ReadPolicyCounters)
	}
	// #3336: span-accumulated runtime/RT_FLOW policy IDs keyed
	// [policySetID, sliceIndex] — the identity the event path logs, so
	// automation can join a policy_id back to a rule.
```

Trace: A read-only `/tmp/a8_b2_trace.go` program used the public configstore and `api.NewServer` surfaces at the frozen HEAD. It committed `security policy-stats system-wide enable`, a `trust -> untrust` permit carrying `then count`, deliberately supplied no dataplane, started the REST server, and fetched `/api/v1/security/policies`. `go run /tmp/a8_b2_trace.go` produced:
```text
status=200 dataplane=unloaded policy_stats=enabled body={"success":true,"data":[{"from_zone":"trust","to_zone":"untrust","rules":[{"name":"counted-permit","action":"permit","src_addresses":["any"],"dst_addresses":["any"],"applications":["any"],"log":false,"count":true,"hit_packets":0,"hit_bytes":0,"policy_id":0,"rule_id":"trust-\u003euntrust/counted-permit"}]},{"from_zone":"-","to_zone":"-","rules":[{"name":"default-policy","action":"deny","src_addresses":[],"dst_addresses":[],"applications":[],"log":false,"count":false,"hit_packets":0,"hit_bytes":0,"policy_id":4294967295,"rule_id":"default-policy"}]}]}
```
This is the normal config-only/degraded server path, not a mocked handler branch. The response explicitly says success, says the permit is counted, and emits numeric zeroes while no runtime counter source exists.

Refutation attempt: I checked whether callers can infer validity from this response, whether an outer status field marks the inventory partial, and whether `then count` is suppressed when the system-wide knob is off. `PolicyInfo` and `PolicyRule` have no dataplane/counter availability field; unlike `GlobalStats.DataplaneDegraded`, `ZoneInfo.PerZoneCountersAvailable`, and `InterfaceStats.Unavailable`, this endpoint carries no local validity marker. The separate `/status` endpoint is not an atomic observation and is not embedded here. The guard is reached for both system-wide policy statistics and per-rule `then count`; the latter explicitly opts a rule into counting even when the system-wide knob is off. Loaded dataplane read failures do not refute this path: they call the reader and return HTTP 500 under #3408, while the unloaded guard leaves `readPolicy=nil`, skips every read, and returns 200. No packet is admitted by this display behavior, and configured permit/deny actions themselves remain accurate.

Final cross-adjudication: Retain the availability-reporting defect. When the dataplane is unloaded the policy inventory deliberately skips every eligible counter read but still emits non-optional packet and byte fields as zero with HTTP 200 and no availability marker. Consumers cannot distinguish an actual zero from an unavailable runtime. This is different from loaded-reader errors, where the handler now returns an error, and from the absence of a default-policy metric. Lane Z6-F003 reproduces the unloaded-dataplane authoritative-zero response and merges here.

HPC/invariant check: This is a management-plane observability defect, not forwarding-path logic; it does not alter session/cache generations, NAT/PBR/filter/screen ordering, UMEM ownership, publication, HA forwarding, or packet-path allocation. The current inventory walk is bounded by configured policy count. A fix should preserve that cost and avoid probing counters per rule: determine counter-source validity once, keep the existing bulk snapshot when loaded, and project one availability state across eligible rules/default policy. HA semantics should identify the local node and must not imply peer counters are included.

Why it matters: During degraded/config-only operation, incident tooling can interpret `0` as “this counted permit/default deny has never matched” when the appliance has no counter source at all. That masks policy-deny and permit activity exactly when dataplane health is already uncertain, conflicts with the API's established unavailable-not-zero security-counter contract, and can produce false compliance or troubleshooting conclusions.

Fix direction: Add an explicit policy-counter availability state to the REST inventory, preferably at `PolicyInfo` or response scope with per-rule eligibility distinguished from disabled counting. When the dataplane is unloaded, mark eligible system-wide, `then count`, and default-policy counters unavailable instead of emitting unqualified zeroes; retain zero with a disabled/not-collected state for ineligible rules. Keep loaded read failures fail-loud as today. Mirror the state in gRPC/text surfaces or define a shared projection type, and add tests for loaded/zero, loaded/read-error, unloaded/system-wide-enabled, and unloaded/`then count`-only cases.

Labels: api, security-policy, counters, degraded-status, observability, false-zero, resource-semantics, tests

Dedup note: Searched the frozen v3 dedup index for policy counters combined with unavailable, unloaded, degraded, authoritative, and zero. #3345/#3408 and the prior fable-review entry cover a loaded counter bridge returning an error that was swallowed; current code fixes that root by returning HTTP 500. This finding is the distinct pre-reader `!IsLoaded` guard: no read/error occurs and the endpoint returns success with eligible counters. The prior RETH status omission and uncapped ping size were separately found and suppressed. Cross-adjudication: Searched the complete index for unloaded policy counters, availability markers, authoritative zeroes, and policy inventory. #3345/#3408 own loaded read errors; #3681 owns independently available kernel host-inbound counters on degraded boot; audit-178 owns flow-session summary literals; avo-review-001 owns missing default-policy metrics. None covers this IsLoaded guard and REST policy-row representation. Z6-F003 was compared with loaded-reader errors and prior counter omissions; its absent-reader branch and availability-schema fix match this source canonical exactly. Corroborating inputs merged: lane:Z6-F003.

### C180-020: Unknown security-log transport tokens silently downgrade to plaintext UDP

Title: Unknown security-log transport tokens silently downgrade to plaintext UDP

Severity: Medium

Confidence: High

Evidence: `pkg/logging/syslog.go:261` dispatches only the two stream protocols explicitly and treats every other token as UDP; the public constructor accepts the token without validation.
```go
func (s *SyslogClient) dial() (net.Conn, error) {
	switch s.protocol {
	case "tcp":
		return s.dialTCP()
	case "tls":
		return s.dialTLS()
	default:
		return s.dialUDP()
	}
}
```

Trace: Runtime reproduction from the frozen worktree: `go run /tmp/review-probe-A9-b1/main.go` called `NewSyslogClientTransport(..., "tls-typo", nil)` against a local UDP listener. Output was `constructor client_non_nil=true err=<nil>`, `send err=<nil>`, and `udp_received=true bytes=41 read_err=<nil>`. Production caller trace is `pkg/daemon/daemon_system.go:112-124`: the compiled `stream.Transport.Protocol` is passed directly to this constructor. The strict schema rejects unknown values, but the campaign's persisted/HA lenient path can retain typed values that did not pass a current strict commit.

Refutation attempt: I checked the strict schema (`pkg/config/schema_security.go`, enum `udp|tcp|tls`) and the strict regression test. That guard refutes admission through a normal local commit, but it does not make this runtime default safe for tolerant load/HA compatibility, and the constructor is exported. I also tested whether the constructor itself returns an error for an unknown token; it returned a live client and transmitted UDP. An empty protocol intentionally means UDP and is not the finding.

Final cross-adjudication: The runtime defect survives the strict commit-time enum gate: lenient persisted or peer-synced state preserves an unknown protocol, and the logging constructor silently sends it as UDP. This can disclose security telemetry in plaintext while the retained configuration names a non-UDP transport.

HPC/invariant check: This is not a dataplane packet-admission change and adds no hot-path work. It violates the fail-closed compatibility and crypto invariant: malformed/unknown security telemetry transport state must disable/reject the stream, never convert a requested secure stream into unauthenticated, unencrypted UDP. Resource lifetime remains bounded in the reproduced path.

Why it matters: A typo or newer transport value arriving through persisted/HA state can leak policy names, zones, addresses, NAT tuples, and session metadata in plaintext while configuration/status still retains the non-UDP token. Operators can believe secure logging is configured although the wire transport is UDP.

Fix direction: Validate `protocol` in `NewSyslogClientTransport` before allocating/dialing. Accept only empty/`udp`, `tcp`, and `tls`; return `(nil, error)` for every other value. Keep empty as the documented UDP default. Add constructor and daemon lenient-load tests asserting unknown values create no socket/client and emit a visible configuration/apply error.

Labels: logging, syslog, crypto, fail-closed, lenient-config, HA-compat, truthful-attribution

Dedup note: No matching root was found in `dedup-index.txt`. Existing #2008 coverage is the strict commit-time enum gate; this finding is the distinct runtime/tolerant-path fallback that converts an unknown token to UDP. Existing #3350 concerns unsupported TLS profiles, not unknown protocol dispatch. Cross-adjudication: Searched the full dedup index for syslog transport, unknown token, UDP fallback, plaintext, NewSyslogClientTransport, #2008, and #3350. Closest is PR #2012's strict schema-only H8 fix; it does not cover the lenient/runtime admission mechanism.

### C180-021: AF_XDP packet-processing documentation states an obsolete non-SYN shim drop

Title: AF_XDP packet-processing documentation states an obsolete non-SYN shim drop

Severity: Low

Confidence: High

Evidence: `docs/afxdp-packet-processing.md:32-33` says non-SYN TCP without a live BPF session is dropped, but `userspace-xdp/src/lib.rs:584-645` now redirects all ordinary session misses and delegates stale RST/FIN handling to `poll_descriptor` strict-syn-check logic.

Trace: The shim's default session-miss arm reaches metadata construction and XSK redirect. Rust tests prove bare RST/FIN misses install no session while other non-handshake misses are not described by the obsolete XDP rule.

Refutation attempt: `is_connection_initiating` remains in the shim source but no longer controls the ordinary miss action. No later paragraph qualifies line 32 as historical.

Final cross-adjudication: The packet-processing document still states that the XDP shim drops ordinary non-SYN session misses, while current code redirects them and leaves only the Rust bare RST/FIN guard. This is a concrete, reachable documentation-contract defect that can misdirect validation toward the wrong enforcement layer, with Low operational impact.

HPC/invariant check: Documentation-only correction has no runtime effect; it should name the Rust cold-path guard and avoid promising a broader deny than source implements.

Why it matters: Operators and reviewers can infer the wrong enforcement layer and design tests that miss the actual session-miss security boundary.

Fix direction: Replace item 7 with the current all-misses-to-userspace contract and cite the Rust bare RST/FIN guard; add a documentation drift check for the source comment or named regression.

Labels: documentation, xdp-shim, session-miss, strict-syn-check, architecture, drift

Dedup note: No matching root was found in the immutable dedup index or accepted batch findings. Cross-adjudication: Searched every matching prior final for afxdp-packet-processing, non-SYN shim drops, session misses, and strict_syn_check. Prior reports discuss the runtime behavior and #4400 guard, but none reports or owns this stale documentation statement.

### C180-022: TX ring backpressure recovery allocates on the overloaded packet path

Title: TX ring backpressure recovery allocates on the overloaded packet path

Severity: Low

Confidence: High

Evidence: `userspace-dp/src/afxdp/tx/transmit/finalise.rs:37` creates a fresh retry vector for every successful prepared finalization and grows it on a partial insert; the zero-insert path separately allocates a `String` for the retry error.
```rust
let mut sent_packets = 0u64;
let mut sent_bytes = 0u64;
let mut retry_tail = Vec::new();
for (idx, req) in binding.scratch.scratch_prepared_tx.drain(..).enumerate() {
    if idx < inserted as usize {
        remember_prepared_recycle(&mut binding.tx_pipeline.in_flight_prepared_recycles, &req);
        sent_packets += 1;
        sent_bytes += req.len as u64;
    } else {
        retry_tail.push(req);
```

Trace: The full `cargo test` run exercised prepared TX unwind and recycle tests (`transmit_batch_oversized_unwind_preserves_pending_order`, local/foreign prepared recycle cases) without ownership failures, but there is no forced partial/zero XSK reservation test for `finalise_prepared`. Static branch tracing shows partial insertion pushes at least one element into a zero-capacity `Vec`, invoking heap growth exactly during ring pressure; zero insertion constructs an owned retry `String`.

Refutation attempt: `Vec::new()` alone does not allocate, full-prefix insertion leaves it empty, and partial XSK reservations may be uncommon. The issue is therefore limited to congestion/recovery, not steady-state line-rate forwarding, and is kept Low severity/confidence rather than treated as a correctness defect.

Final cross-adjudication: The performance claim is directly established, although its impact remains Low. A zero TX-ring insertion allocates an owned String, and a partial insertion pushes the unaccepted suffix into a zero-capacity Vec, allocating during congestion. Partial insertion is not hypothetical because the XSK adapter deliberately restores reserve-up-to semantics. Ownership and retry order remain correct, so this is an overload latency issue rather than packet corruption.

HPC/invariant check: Packet TX and overload recovery should remain allocation-free and bounded. This code preserves UMEM ownership and retry ordering, but violates the allocation half of that invariant when `inserted < staged.len()` and on the owned error string paths.

Why it matters: Allocator work and potential contention occur exactly when the TX ring is saturated, increasing tail latency and reducing recovery throughput. Repeated partial reservations can amplify an overload episode even though packet ownership remains correct.

Fix direction: Move retry-tail storage into preallocated `WorkerScratch`, or restore the unaccepted suffix directly to the front without a fresh vector. Replace stringly `TxError` variants with static reason enums (format only on the slow diagnostic boundary). Add forced zero/partial reservation tests with an allocation counter.

Labels: performance, tx, backpressure, allocation, hft, test-gap

Dedup note: No exact prior finding for `finalise_prepared` retry-vector/owned-error allocation was found. This is distinct from prior CoS admission formatting fixes and from UMEM leak/double-recycle findings, which are fixed and remained sound here. Cross-adjudication: Searched the complete index for finalise_prepared, prepared TX, retry_tail, partial reservation, ring backpressure, zero insert, and overload allocation. No prior defect owns this path. The closest c673b86ca refactor merely claimed behavior-preserving zero allocation, while prior packet-path allocation findings concern filter Arcs, CoS staging, or NAT64 buffers and have different owners and triggers.

### C180-023: Malformed DNAT prefix metadata silently narrows to one exact host

Title: Malformed DNAT prefix metadata silently narrows to one exact host

Severity: Low

Confidence: High

Evidence: `userspace-dp/src/nat/destination.rs:319`
```rust
                    // Unparseable prefix: fall back to the host
                    // `destination_address` if it parses, else drop the entry
                    // (fail-closed, like an unparseable host destination).
                    // #4718: surface the drop loudly instead of a silent skip.
                    Err(_) => match snap.destination_address.parse::<IpAddr>() {
                        Ok(ip) => DnatDest::Host(ip),
                        Err(_) => {
```

Trace: Runtime command `cargo test nat::tests_ -- --test-threads=1` passed all 225 NAT tests, including valid prefix LPM and malformed destination/pool telemetry. The matrix has no malformed non-empty `destination_prefix` case. Driving the shown classifier with `destination_prefix="203.0.113.0/not-a-mask"` and valid additive base `destination_address="203.0.113.0"` selects `DnatDest::Host(203.0.113.0)` and never calls `record_parse_error`; subsequent lookup translates only the base host while `203.0.113.1` and the rest of the intended block miss DNAT. This is the exact pre-3164 narrowed behavior despite a non-empty new-field signal.

Refutation attempt: The normal Go builder canonicalizes prefixes, so ordinary same-version commits do not emit this pair. That does not refute the helper-boundary contract: the field is explicitly additive for mixed-version compatibility, lenient/HA snapshots are named threat paths in the module, and sibling malformed destination/pool fields are surfaced at this same boundary. Treating a non-empty but invalid new field as if it were absent conflates an old producer with corrupt/incompatible metadata. No validator in `DnatTable::from_snapshots` checks consistency between the base and prefix before the fallback.

Final cross-adjudication: A nonempty malformed destination_prefix is treated as absent when destination_address remains parseable, silently changing a requested prefix rule into one exact-host rule and recording no parse error. This survives as a helper-boundary integrity and observability defect. Severity is Low because the ordinary same-version Go builder emits only canonical prefixes, the fallback narrows rather than widens translation, and exploitation requires corrupt, incompatible, or manually malformed internal snapshot metadata. Lane Z3-F005 is direct helper-boundary corroboration and merges into this source root.

HPC/invariant check: Snapshot parsing is apply-time only, so rejecting or loudly dropping this row has no packet hot-path cost, allocation, lock, or cache impact. Invariant violated: a present additive prefix is authoritative; it must either hydrate as that prefix or fail visibly, never silently downgrade to a different match cardinality.

Why it matters: A mixed-version, corrupt, or leniently loaded DNAT block can publish successfully while translating only its network base. Connections to the remaining public addresses bypass the configured translation and may route elsewhere or fail, while parse-error counters falsely report a clean apply.

Fix direction: If `destination_prefix` is non-empty and fails `IpNet` parsing, record a parse error and skip the row (or make DNAT snapshot construction transactional and retain prior state). Reserve exact-host fallback solely for an actually absent field from an older producer. Add malformed-prefix-with-valid-base and base/prefix-family-consistency tests, including parse-error telemetry and no installed exact fallback.

Labels: nat, dnat, snapshot-integrity, mixed-version, fail-closed, observability, vsrx-parity, tests

Dedup note: Distinct from closed DNAT prefix support/strict-validation issues #3029/#3164 and prior malformed destination/pool-address telemetry. Those concern missing prefix support or wholly unparseable rows; this root is the current helper's silent downgrade of a present malformed additive prefix to a valid but narrower exact-host rule. Cross-adjudication: Searched the full corpus for destination_prefix, malformed DNAT prefix, exact-host fallback, narrowing, and parse telemetry. #3029/#3164 concern a valid prefix being rejected or omitted before prefix support, whereas this path receives a present but invalid additive field. #4718 surfaces dropped malformed rows but misses the successful host fallback. The symptom resembles #3029, but the defect mechanism and helper-boundary affected surface differ. The lane's malformed-present-prefix trace was compared with this source and with historical missing-prefix support; its presence-versus-absence distinction and fix are identical to this input. Corroborating inputs merged: lane:Z3-F005.

### C180-024: TCP-flags grammar discards unbalanced and reversed parentheses

Title: TCP-flags grammar discards unbalanced and reversed parentheses

Severity: Low

Confidence: High

Evidence: `pkg/config/tcp_flags.go:132`
```go
                "tcp-flags %q: logical OR (\"|\") is not representable by the firewall dataplane; split the disjuncts into separate terms", expr)
        case "!":
            pendingNeg = !pendingNeg
            continue
        case "(", ")":
            if pendingNeg {
                return 0, 0, false, fmt.Errorf(
                    "tcp-flags %q: a negated group is a disjunction (De Morgan) and is not representable by the firewall dataplane", expr)
            }
            continue
```

Trace: The exported parser was exercised directly in `go run /tmp/repro_a3b5.go`. Inputs `"(syn"`, `"syn)"`, and `"syn)("` all returned `required=0x2 forbidden=0x0 ok=true err=<nil>`. The strict firewall compiler therefore cannot distinguish these malformed expressions from `syn`; current runtime matching is not widened because the SYN bit survives, but strict grammar and operator feedback are wrong.

Refutation attempt: Reviewed the lexer, pending-negation, segment-operand, contradiction, and operator-only guards and ran the assigned TCP flag tests. None tracks parenthesis depth/order, and no upstream parser removes or validates parentheses inside the quoted value. Existing #4714/#5455 tests cover dangling `!` and `&`, not grouping balance.

Final cross-adjudication: ParseTCPFlagsExpression tokenizes parentheses but discards every non-negated open or close without tracking depth or ordering. Thus malformed `(syn`, `syn)`, and `syn)(` commit as ordinary SYN constraints. The packet mask is not widened in these examples, but strict grammar silently normalizes invalid security-filter syntax, making this a distinct Low correctness and auditability defect. Lane Z1-F006 reproduces the same parenthesis-balance parser defect and merges here.

HPC/invariant check: Parsing is commit-time over a bounded authored string. A depth counter and “close requires open” check are O(n), allocation-free beyond the existing token slice, and do not affect Rust packet matching. Lenient behavior can warn while retaining the currently derived mask because doing so does not broaden admission.

Why it matters: Strict commit accepts malformed firewall expressions and silently normalizes them, concealing typos in security filters and diverging from the claimed grammar. Today’s examples preserve the SYN constraint, so this is correctness/auditability debt rather than a demonstrated packet-admission bypass.

Fix direction: Track parenthesis depth and ordering, reject a close at depth zero and nonzero depth at end, and reject empty/misordered groups. Add strict compiler tests for leading close, missing close, reversed pairs, nested balanced groups, and lenient warning behavior.

Labels: config, firewall-filter, parser, strict-validation, tests

Dedup note: The frozen dedup entries for TCP flags cover dropped expressions, dangling negation, and operator-only inputs. No entry covers unbalanced or reversed parenthesis acceptance. Cross-adjudication: Searched the full index and all prior audit reports for tcp-flags parentheses, balance, and reversed delimiters. #3076 owns dropped unrepresentable expressions, #4714 dangling negation, and #5455 operator-only/empty operands; none tracks balanced-parenthesis state while preserving a parsed mask, so this mechanism and Low impact remain independent. Z1-F006 was compared with the source and prior dangling-operator findings; balance/order tracking for parentheses is the same campaign mechanism and remains distinct from those prior roots. Corroborating inputs merged: lane:Z1-F006.

## Medium Confidence Findings

### C180-025: A fresh passive WireGuard listener is denied by restricted kernel host-inbound policy

Title: A fresh passive WireGuard listener is denied by restricted kernel host-inbound policy

Severity: Medium

Confidence: Medium

Evidence: `userspace-xdp/src/lib.rs:548`, `userspace-xdp/src/lib.rs:562`, `pkg/config/host_inbound_tokens.go:336`, `pkg/daemon/daemon_nft.go:626`, `test/incus/wg-interop.sh:660`
```rust
// `wg_listen_port` load, not the protocol/port/local-destination
// tests. This keeps the non-WG datapath byte-for-byte on its prior
// instruction path (the bare per-packet `wg_listen_port` load+compare
// measurably regressed v6 best-effort retransmits at line rate).
if (ctrl.flags & USERSPACE_CTRL_FLAG_WG_RX) != 0 && wg_steer_to_kernel(ctrl, &parsed) {
    return Ok(cpumap_or_pass(ctrl));
}
```

Trace: For the configured listen port, the XDP shim deliberately steers local-destination WireGuard UDP to Linux so the Rust control thread's kernel socket can receive it. The host-inbound service SSOT has no `wireguard` token or dynamic listen-port tuple, and `buildHostInboundFilterPayload` emits no WireGuard exception. On a restricted zoned address a first inbound handshake is conntrack `NEW`, misses the configured service accepts, and reaches the `xpfhi_` catch-all drop; on an addressed unzoned interface it reaches the #4420 catch-all. The overlay generated a restricted-zone table and confirmed that no UDP/51820 admission precedes the drop. The interop harness first makes xpf the initiator; its later responder phase reuses the same 51820/51820 tuple without an explicit conntrack flush, so it does not exercise a fresh passive listener.

Refutation attempt: Responses to an xpf-initiated handshake are admitted as established, which explains existing interop success. `system-services all` also admits the listener, but requiring a blanket host opening is not a scoped WireGuard contract. This is distinct from the documented second-tunnel limitation: even the first configured port is correctly steered and then denied at kernel input.

Final cross-adjudication: The configured WireGuard listen port is deliberately steered to the kernel, but a clean passive handshake on a restricted zoned address has no WireGuard host-inbound token or dynamic exception and reaches the NEW-packet catch-all drop. The supported responder workflow can therefore depend on stale initiator-created conntrack or a blanket all-services opening.

HPC/invariant check: The shim's local-destination and exact-port checks must remain unchanged so transit/DNAT UDP is never shunted around userspace policy. Admission can be generated at config time and scoped to the active listener's local address/interface without adding Rust hot-path work.

Why it matters: A supported responder-only WireGuard configuration can remain unavailable after boot or conntrack expiry, while health checks based on an initiator-first sequence pass. The coarse drop counter increments, but there is no tuple-rich kernel log tying it to the configured tunnel.

Fix direction: Define whether a configured WireGuard listener implies host admission or requires an explicit dynamic `wireguard` service. Generate an exact listen-port, local-address/interface-scoped kernel rule accordingly. Add a clean-state live test that removes the xpf peer endpoint, flushes the relevant UDP conntrack tuple, starts the external peer as initiator, and proves handshake plus inner traffic without `system-services all`.

Labels: host-inbound, WireGuard, XDP, kernel-socket, conntrack, false-deny, availability, Z4

Dedup note: No matching host-inbound root appears in the frozen index. The documented multi-tunnel shim limitation concerns steering only one configured listen port; this finding concerns admission of that already-steered first port. Cross-adjudication: Searched all prior finals for WireGuard listener, responder, host-inbound, system-services, and port 51820. Prior WireGuard findings concern steering, multiple ports, and endpoint learning, not admission of the already-steered first port. Confidence is Medium because repository policy does not clearly state whether tunnel configuration implies admission.

### C180-026: Shutdown-abandoned trap jobs are omitted from the drop counter

Title: Shutdown-abandoned trap jobs are omitted from the drop counter

Severity: Low

Confidence: Medium

Evidence: `pkg/snmp/traps.go:427` exits immediately on stop, leaving buffered jobs abandoned without adding them to `trapsDropped`:
```go
	for {
		select {
		case <-stop:
			return
		case job, ok := <-queue:
			if !ok {
				return
			}
```
`pkg/snmp/agent.go:819` closes that stop channel but neither drains nor accounts for the pending queue:
```go
	a.stopped = true
	if a.lifeCancel != nil {
		a.lifeCancel() // unblock the ctx-watcher goroutine
	}
	if a.trapStop != nil {
		close(a.trapStop) // tell the trap worker to abandon its queue
	}
	if a.conn != nil {
		a.conn.Close()
```

Trace: The overlay runtime test blocked the in-flight sender, queued three additional jobs, started `Stop`, then released the sender. The worker observed stop and exited as designed. The test logged `shutdown left 2 queued jobs and trapsDropped=0`; one queued job can be selected and rejected by the worker's second stop check, while the remaining two stay buffered, and none is counted. Queue-full and post-stopped enqueue paths do increment the same counter, so the total specifically omits shutdown abandonment.

Refutation attempt: Checked whether shutdown abandonment is intentionally excluded, counted by the daemon reconcile layer, or surfaced through another metric. The field and comments describe `trapsDropped` generally; `Stop` explicitly calls queued jobs abandoned, no caller receives a count, the queue is not closed/drained, and repository search finds no other increment or exported accounting path. The no-post-stop-delivery safety invariant is correct and must be preserved; only observability is wrong.

Final cross-adjudication: Stop correctly prevents post-reconfiguration delivery, but accepted jobs abandoned at that boundary are omitted from the same drop total used for queue-full and post-stop rejection. The impact is limited to low-severity lifecycle accounting because the queue is bounded and the safety shutdown behavior is correct.

HPC/invariant check: Preserve bounded, nonblocking producer behavior and the stop-before-send invariant. Counting `len(queue)` alone must be synchronized with worker exit to avoid double-counting the job selected concurrently; a clean design has the worker account a dequeued-but-unsent job and drain/count remaining buffered jobs after stop, or transfers queue ownership to `Stop` only after `trapWG`. No forwarding, policy/zone, HA, UMEM, or cryptographic invariant is affected.

Why it matters: Link-state traps are commonly lost exactly during SNMP disable, target rotation, or daemon shutdown. Reporting zero drops while retaining and discarding queued notifications hides the observability loss and makes operational audits falsely conclude that every accepted notification was delivered.

Fix direction: Define accepted/sent/failed/dropped counters explicitly. On stop, have the sole queue owner count every dequeued-but-unsent and buffered-abandoned job exactly once before exit, then expose those counters through the existing metrics/status surface. Extend `agent_stop_leak_4916_test.go` to assert no post-stop send, zero retained queue entries, and exact accounting under the blocked-sender race.

Labels: observability, snmp-traps, lifecycle, resource-safety, counter-correctness

Dedup note: Not a duplicate of the prior `Agent.Stop` goroutine leak/no-post-delivery finding. That root is fixed and suppressed here; this finding is the residual false accounting and retained buffered resources after the correct stop signal. Cross-adjudication: Searched the full index for trap shutdown, abandoned queue, dropped accounting, trapsDropped, and Stop. Audit 179's stale-authorized-job root and #4916 concern delivery/lifecycle safety, not residual drop accounting, and no same-root prior report was found.

## Low Confidence Findings

No canonical findings in this confidence tier.

## Coverage & Verification Summary

- Source coverage: 2,679 / 2,679 files, partitioned exactly once across 30 accepted batches.
- Module ledger: every assigned source file has a finding or an explicit negative result.
- Cross-layer lanes: 7 / 7 tooling-v3 acceptance records; 334 policy-relevant non-source files reviewed.
- Raw source adjudication: 35 / 35 explicit decisions; 21 retained before cross-lane merging.
- Cross-adjudication: 60 / 60 explicit decisions; 26 canonical roots.
- Top-tier verification: all 3 surviving Critical/High findings have coordinator PASS records and independent hostile review. One provisional source High was downgraded to Medium; the lane-only High's duplicate-versus-severity-escalation disagreement was resolved explicitly in the cross-layer section.
- Main checkout remained clean at the immutable base throughout the review.

## Suggested Issue Split

Create one issue per canonical root unless two rows explicitly share a fix boundary. Use `vsrx-parity` for any row whose Labels or impact describes Junos/vSRX behavior. Preserve the audit ID in each issue for traceability.

| Audit ID | Severity | Confidence | Suggested issue title | Labels |
|---|---|---|---|---|
| C180-001 | High | High | Worker-visible validation and forwarding rotate as separate generations | snapshot-publication, worker-rotation, ArcSwap, generation, flow-cache, policy-invalidation, concurrency, fail-open |
| C180-002 | High | High | Planned failover can promote a peer with stale security policy because session readiness has no applied-config epoch | lane:Z5, security, fail-open, false-deny, ha, session-sync, policy-generation, snapshot-publication, v4-v6, tests |
| C180-003 | High | High | Standby config-sync tail failures permanently bypass policy session invalidation | security, HA, sessions, policy-rematch, default-policy, runtime-ordering, fail-open, Z5 |
| C180-004 | Medium | High | A per-interface IKE or ident exception is widened to every interface in the zone | host-inbound, per-interface, IKE, IPsec, ident-reset, junos-host, nftables, false-allow, Z4, vsrx-parity |
| C180-005 | Medium | High | Kernel-established inbound host sessions retain authorization after coarse policy tightening | host-inbound, conntrack, established, configuration, authorization, kernel, Rust, false-allow, Z4 |
| C180-006 | Medium | High | Unbuildable Time Exceeded and PTB attempts consume global reply tokens and can starve other interfaces | generated-control, ICMP, IPv4, IPv6, PMTUD, resource-accounting, false-deny, DoS, Z3-handoff, tests |
| C180-007 | Medium | High | Filter, policy, host-inbound, and embedded-ICMP classifiers can read L4 semantics from Ethernet slack | zone-policy, fail-open, false-deny, parsing, IPv4, IPv6, fragments, host-inbound, firewall-filter, session |
| C180-008 | Medium | High | Egress-filtered reject replies drain the per-zone reject bucket before being discarded | zone-policy, reject, output-filter, rate-limit, availability, counters, IPv4, IPv6 |
| C180-009 | Medium | High | Policy counter clear accepts trailing selectors but still clears every policy | cli, policy, counters, destructive-command, fail-closed, observability, api-contract |
| C180-010 | Medium | High | DDNS ownership state is read without a size bound before validation | resource-bounds, availability, ddns, persisted-state, fail-closed, CWE-770, lane-Z6 |
| C180-011 | Medium | High | Policy simulator cannot represent non-first fragments and reports permit where the dataplane applies the fragment-associated deny | Z6-primary, policy-simulator, management-parity, fail-open-diagnostic, false-deny-avoidance, fragments, IPv4, IPv6, applications, CLI, REST, gRPC, tests, vsrx-parity |
| C180-012 | Medium | High | Cluster marker I/O errors bypass both standalone-cut HA safety gates | upgrade, HA, fail-open, availability, operational-safety, test-gap |
| C180-013 | Medium | High | Conflicting scalar leaves in a direct application silently keep only the last condition | compiler, applications, protocol, ports, icmp, ALG, strict-commit, lenient-load, HA-sync, fail-open, false-deny, default-policy, tests, vsrx-parity |
| C180-014 | Medium | High | Lenient policy compilation publishes missing or discarded constraints as wildcard permits | zone-policy, compiler, lenient-load, HA-sync, fail-open, permit-widening, applications, scoped-global, tests |
| C180-015 | Medium | High | Route-filter validator accepts a match keyword in the CIDR slot and commits a match-none policy | config, routing, schema-walker, frr, false-deny, strict-lenient |
| C180-016 | Medium | High | Zone collision quarantine drops a multi-zone deny from surviving scope members | security-policy, zone-identity, collision-quarantine, scoped-global, lenient-load, HA, fail-open, snapshot-lowering |
| C180-017 | Medium | High | Policy invalidation failures are logged but the commit still succeeds with stale authorized sessions | security, sessions, policy-invalidation, error-propagation, fail-open, IPv4, IPv6, Z5 |
| C180-018 | Medium | High | Match-policies folds mixed per-interface host-inbound posture into an unqualified zone-wide admission | api, match-policies, security-zone, host-inbound, per-interface, false-admission-diagnostic, vsrx-parity, tests |
| C180-019 | Medium | High | Eligible REST policy hit counters become authoritative-looking zeroes when the dataplane is unloaded | api, security-policy, counters, degraded-status, observability, false-zero, resource-semantics, tests |
| C180-020 | Medium | High | Unknown security-log transport tokens silently downgrade to plaintext UDP | logging, syslog, crypto, fail-closed, lenient-config, HA-compat, truthful-attribution |
| C180-021 | Low | High | AF_XDP packet-processing documentation states an obsolete non-SYN shim drop | documentation, xdp-shim, session-miss, strict-syn-check, architecture, drift |
| C180-022 | Low | High | TX ring backpressure recovery allocates on the overloaded packet path | performance, tx, backpressure, allocation, hft, test-gap |
| C180-023 | Low | High | Malformed DNAT prefix metadata silently narrows to one exact host | nat, dnat, snapshot-integrity, mixed-version, fail-closed, observability, vsrx-parity, tests |
| C180-024 | Low | High | TCP-flags grammar discards unbalanced and reversed parentheses | config, firewall-filter, parser, strict-validation, tests |
| C180-025 | Medium | Medium | A fresh passive WireGuard listener is denied by restricted kernel host-inbound policy | host-inbound, WireGuard, XDP, kernel-socket, conntrack, false-deny, availability, Z4 |
| C180-026 | Low | Medium | Shutdown-abandoned trap jobs are omitted from the drop counter | observability, snmp-traps, lifecycle, resource-safety, counter-correctness |
