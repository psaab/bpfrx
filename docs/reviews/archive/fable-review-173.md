# xpf Refactor / Monolith Coverage Audit — fable campaign 173

1. **Base commit reviewed**: `e87d57e2d55784482c8285112d5cd941fc5a2df5` (master, after `git pull --rebase`, 2026-07-08 — the only repo mutation performed).
2. **Output path**: `/tmp/fable-review-173.md`
3. **Method**: 1 dedup agent over the prior campaign corpus (`/tmp/{ps,codex,agy,opus,fable}-review-*.md`, ~30 reports) + **10 parallel module-audit agents** (A1–A5 Rust dataplane, A6–A10 Go control plane), each producing a file-by-file inspection log and findings in the required field format; synthesized and cross-deduped here. Static inspection only; no repository source file was modified. Headline metrics were spot-verified against HEAD (e.g. `poll_binding_process_descriptor` measured at exactly **4,724 LOC**, lines 603–5326).

## Executive summary

**115 blocks total: 57 High-confidence findings, 11 Medium, 25 Low (including recorded do-not-split negatives), 22 status corrections to the prior catalog.** The ≥20 non-duplicate target is met several times over without padding; every block carries a dedup tag (NEW / INCREMENT / STATUS-UPDATE / D-NEGATIVE) against the tracked backlog (#4404–#4422) and prior campaign catalogs.

The load-bearing results:

1. **The #4404 god-function is 3.4× bigger than the issue records.** `poll_binding_process_descriptor` (`afxdp/poll_descriptor/mod.rs`) is **4,724 LOC** at HEAD (verified), not the 1,368 in the catalog — helper peels landed while the trunk kept growing. A1-F1 gives the staged extraction plan (NAT64 pre-routing cold block ~487 LOC first; `StageOutcome` return type to preserve the #2208 recycle-once contract), class B with cargo-asm + txn_* differential-test gates.
2. **Systemic heatmap distortion — the modularity SSOT over-reports Rust monoliths.** `scripts/refactoring-audit.sh` counts inline `#[cfg(test)] mod tests` (documented, but the effect is now large) and its exclusion patterns miss the new `nat/tests_*.rs` naming from the #4409 split, so two pure test files sit in the committed REFACTOR tier. Corrected production LOC: `poll_stages.rs` 972 (not 3,527), `reject_reply.rs` 414 (not 2,174), `cold_path_hist.rs` ~950 (not 1,866), `state_writer.rs` and `slowpath.rs` similarly inflated. Several cataloged split proposals are **downgraded to D** on the corrected numbers (A1-F2, A1-F5/F6, A3-F4, A4-F13, A5-F5). The committed artifact also lags HEAD in the other direction: `queue_service/mod.rs` crossed 2,000 and `poll_descriptor/mod.rs` is 6,042 vs the recorded 3,468.
3. **Fresh uncataloged god-functions, both planes.** Go: `runUniformGates` is one **1,659-LOC function** (~78 ordered fail-open gates; order already pinned by golden/canary tests → safe table-drive, A6-F1); `compileZones` **931 LOC** fusing five actuation domains incl. the fail-open unmanaged-interface bring-down (A7-F-A7-1); `daemon_run.go::Run` **1,692 LOC** (A8-F1); `newCollector` **1,886 LOC** (A9-F1, measured); `Runner.Run` 431 LOC in upgrade/cutover.go (A10-F-2). Rust: `worker_loop` ~1,300 LOC with cold cadence work fused around the hot poll (class C, A1-F3); `acquire_v8_with_cause` 277-LOC hot CAS fn fused with ~30 cold status getters (A3-F5); two per-packet classify god-fns in `tx/cos_classify.rs` (A3-F6).
4. **Cross-surface duplication with proven drift.** The session view/filter/projection is implemented three times (REST, gRPC, CLI) and has **already diverged** (egress-interface resolution guarded on `fibIfindex != 0` in REST but not gRPC) — A9-F3 upgrades the cataloged dedupe from hygiene to correctness.
5. **Hot-path perf bugs confirmed still open, adjacent to planned splits** (fix travels with the refactor): per-resolution `DEFAULT_V4_TABLE.to_string()` heap alloc (A2-F1); session hit-path `metadata.clone()` Arc-refcount churn (A4-F5); NAT allocator GC sweep under the shared Mutex (A4-F8). **`SessionTable`/`SessionEntry` have no `size_of` pin today** (A4-F4) — the pin must land BEFORE any field-touching refactor. `ForwardingState` regressed from 55 to **64 fields** (A2-F7).
6. **Honest negatives recorded** so the next campaign doesn't re-propose them: `cmdtree/tree.go` is a declarative table, not a god-fn (D-correction of the cataloged split, A9-F11); `xsk_ffi.rs`, `userspace-xdp/lib.rs` (verifier-constrained), `protocol/binding.rs`, `retirement_boundary_canary_test.go`, and the previously recorded D-class set were all re-verified. One D-class went the other way: `screen/mod.rs`'s D is **partially stale** — `check_packet_with_zone_id_opts` has grown into a ~330-LOC inline god-fn (A4-F10).

## 3. Duplicate-suppression summary

Full catalog in the dedup appendix of this campaign's working set; condensed here.

- The repo carries its own modularity SSOT: `docs/refactoring-audit.md` (rules; ≥2,000 LOC REFACTOR tier, 1,500–1,999 WATCH) + committed `docs/refactoring-audit-current.txt` heatmap with a `make audit-check` drift gate. The committed artifact **lags HEAD materially** (see finding A1-F6).
- Open tracked refactor issues deduped against: **#4404** (poll_binding_process_descriptor; inc-1 `debug_log_throttle` landed), **#4407** (Daemon god-struct DONE at 756 LOC; `applyConfigLocked` fn still open), **#4408** (TX `enqueue_pending_forwards` + waterfill; inc-1 landed), **#4409** (NAT allocator/source; `nat/tests.rs` split DONE), **#4421** (policy.rs / nat64 / neighbor / SessionTable / ForwardingState umbrella; `SnapshotIntegrityError` extraction DONE at HEAD), #4422 (not refactor).
- Prior campaigns (ps-review-010/011, agy-review-171, codex-review-171/173) cataloged most ≥1,500-LOC files with proposed decompositions and A/B/C/D classes. This campaign therefore reports **only**: status corrections, materially new decomposition/hot-path detail, NEW uncataloged god-functions/structs, and D-class results. Every finding block carries an explicit `Dedup tag` and `Dedup note`.
- D-class DO-NOT-SPLIT decisions already on record (re-verified this run, not re-proposed): `flow_cache_hit`, `evaluate_policy_result_l3_aware`/`try_match_rule`, `cold_path_hist.rs` seqlock/repr(C) structs, `frame/inspect.rs` parser locality, frame build/rewrite codegen, `umem::BindingLiveState`, `tx/rings.rs`, `FlowFairState`, `BindingWorker`, `gre.rs`, `cluster/failover.go`.
- Hot paths named by prior perf findings that constrain every split (per dedup corpus §2): the RX descriptor loop, `worker_loop`, the poll_stages chain, `stage_flow_cache_hit`, forwarding FIB/zone-pair lookups, the TX drain's monomorphized tunnel match + UMEM single-recycle, the waterfill's nanosecond budget + `repr(align(64))` CoS structs, SessionEntry/SessionTable layout, NAT allocator lock, WG stack-buffer crypto, filter eval `#[inline(always)]`, neighbor enqueue alloc-free contract, event_stream/slowpath backpressure + io_uring invariants; Go-side: maps_sync fail-closed ordering + native-endian keys, the ≤1-Status()-per-scrape control-socket rule, `tunnel.go` keepalive generation counters, VRRP advert timing/GARP gates.

### 3b. Status corrections discovered this run (index; full blocks in §6.4)

- FIXED / DONE since the catalog: `schema_validators.go` split (codex-173-1); `compiler_security.go` grab-bag (fable-163 F28); `compileExpanded` god-fn (now a 124-LOC orchestrator — residual is the 98-field `compileOpts` struct); `frame/tcp_segmentation.rs` dead checksum branch (removed in #4384); NAT64 ext-hdr walker 0..6-vs-8 divergence; filter policer SmallVec cap (#4566); dead-counter indices PARTIALLY fixed (#4477 — 2 of 4 bridged); per-domain snapshot builders already discrete (codex-173-3..7 effectively satisfied); manager.go / daemon.go god-structs confirmed fixed (templates to cite).
- GREW / REGRESSED since the catalog: `poll_binding_process_descriptor` 1,368→4,724 LOC; `ForwardingState` 55→64 fields; `queue_service/mod.rs` 1,880→2,058 (crossed REFACTOR); `cluster/sync_conn.go` ~1,515→1,858; `ipsec/policy.go` ~880→1,059; `ValidateConfig` ~1,357→1,534.
- OVER-SCOPED in the catalog (downgraded): `poll_stages.rs` 6-way production split (972 prod LOC — test-inflated tier); `reject_reply.rs`/`cold_path_hist.rs`/`state_writer.rs`/`slowpath.rs` heatmap tiers (test-inflated); `cmdtree/tree.go` split (declarative table).

## 4. File-size / shape inventory (coverage checklist)

Heatmap regenerated at HEAD via `bash scripts/refactoring-audit.sh` (stdout only; the committed artifact was not touched). RAW LOC — see finding A1-F6 for the inline-test caveat; per-file production LOC corrections appear in the inspection logs.

**[REFACTOR] tier (18)**: poll_descriptor/mod.rs 6042 · policy.rs 3598 · nat/tests_pool.rs 3564\* · poll_stages.rs 3527† · compiler_validate_warn.go 3330 · dataplane/userspace/protocol.go 2979 · forwarding/mod.rs 2822 · config/compiler_nat.go 2529 · nat64.rs 2527 · vrrp/instance.go 2417 · daemon_run.go 2329 · coordinator/wg_control.rs 2280 · poll_descriptor/reject_reply.rs 2174† · config/compiler.go 2110 · cmd/cli/show.go 2100 · cos/queue_service/mod.rs 2058 · session/mod.rs 2054 · afxdp/neighbor.rs 2036.

**[WATCH] tier (34)**: surface_a.go 1957 · frr/policy_render.go 1938 · daemon_apply.go 1926 · api/metrics_descriptors.go 1896 · compiler_system.go 1881 · routing/tunnel.go 1877 · cold_path_hist.rs 1866† · cluster/sync_conn.go 1858 · compiler_services.go 1821 · metrics_userspace.go 1819 · frame/inspect.rs 1813 · wg/engine.rs 1805 · dhcp.go 1800 · types/cos.rs 1786 · worker/loop_body/mod.rs 1776 · maps_sync.go 1763 · dataplane/compiler.go 1733 · frame/mod.rs 1710 · event_stream/mod.rs 1693 · policymatch.go 1679 · compiler_validate_strict_filter.go 1660 · compiler_uniformgates.go 1659 · slowpath.rs 1659† · nat/tests_destination.rs 1654\* · worker/mod.rs 1625 · server_diag.go 1602 · frame/wg.rs 1561† · cmdtree/tree.go 1548 · dhcprelay/relay.go 1545 · types_system.go 1544 · userspace-xdp/lib.rs 1541 · screen/mod.rs 1540 · snmp/agent.go 1519 · neighbor_resolver.rs 1512.

\* = pure test file leaking into the production heatmap (script exclusion patterns `tests.rs` / `*_tests.rs` miss the `tests_*.rs` naming introduced by the #4409 split). † = raw LOC dominated by inline `#[cfg(test)] mod tests`; production LOC is far lower (per-file corrections in the inspection logs).

**Test-file mass (separate ledger — review-cost, excluded from the heatmap)**: afxdp/tests.rs 13,598 · filter/tests.rs 8,330 · frame/tests.rs 8,290 · policy_tests.rs 7,161 · session/tests.rs 6,994 · manager_test.go 6,782 · frr_test.go 5,920 · parser_security_test.go 5,805 · session_glue/tests.rs 5,587 · parser_ast_test.go 5,586 · screen/tests.rs 5,395 · forwarding_build/tests.rs 5,042 · sync_test.go 4,717 · cos_classify_tests.rs 4,617 · queue_service/tests.rs 4,384 · coordinator/tests.rs 4,005 · nat64_tests.rs 3,984 · parser_routing_test.go 3,936 · wg/tests.rs 3,909 · retirement_boundary_canary_test.go 3,354 (deliberate gate — D).

Coverage: the 10 module groups partition every production file ≥~800 LOC in both languages plus the mid-band (600–800) via per-group sweeps; the per-group inspection logs below are the coverage proof (every file listed with a verdict, including clean/covered-by-catalog entries).

## 5. File-by-file inspection log (per module group)

### A1-rust-hotpath

| File | Total LOC | Prod LOC | Responsibilities read | Hot-path proximity | Verdict |
|---|---|---|---|---|---|
| `poll_descriptor/mod.rs` | 6,042 | 5,327 | one god-fn `poll_binding_process_descriptor` (603–5326, ~4,724 LOC) = the entire per-descriptor RX loop: parse→L2-learn→GRE-decap→screen→ipsec→session-hit→session-miss(syn-cookie/DNAT/NPTv6/NAT64)→forward-resolve→policy→host-inbound→fabric→HA→terminal-disposition-dispatch→telemetry; + 6 small free fns (junos-host policy, flowless verdict, resolver enqueue, session-limit drop, strict-syn) | **HOTTEST in repo** — RX god-loop | **FINDING F1** (STATUS-UPDATE #4404: fn 3.4× cataloged size) |
| `poll_descriptor/reject_reply.rs` | 2,174 | **414** | 4 cohesive fns: `enqueue_policy_reject_reply`, `enqueue_deny_reply`, `deny_reply_and_emit`, `enqueue_reject_reply` (TCP-RST / ICMP-unreachable synth, budget+rate-limit+output-filter gates, RT_FLOW truthfulness); 1,760 LOC inline `mod tests` (25 tests) | cold generated-reply path (session-miss/terminal) | **FINDING F5** (NEW: prod cohesive → D-NEGATIVE on split; move inline tests) |
| `poll_descriptor/filter.rs` | 1,201 | 639 | 14 small fns: input-filter eval (PBR/non-PBR/log-only/cached-counters/DSCP-sensitive), lo0 filter action, host-inbound-gated lo0, filter-log emit/replay; all ≤73 LOC | on packet path (session-hit + miss + flowless) | **CLEAN** (cohesive; largest fn ~73 LOC) |
| `poll_descriptor/flow_cache_hit.rs` | 521 | 521 | single `stage_flow_cache_hit` (65–521, ~456 LOC): the 90%+ established-flow fast path | **hot fast path** | **D** (catalog D-class confirmed — split kills inlining/icache) |
| `poll_descriptor/cookie_reply.rs` | 509 | 127 | SYN-cookie SYN-ACK / ACK-RST synth; 382 LOC inline tests | cold (session-miss) | **CLEAN** (cohesive) |
| `poll_descriptor/nat_exception.rs` | 125 | ~110 | `#[cold] #[inline(never)]` SNAT decision + failure recorder, byte-lifted from mod.rs (#1697) | cold (session-miss) | **CLEAN / D** (correctly cold-extracted) |
| `poll_descriptor/rx_telemetry.rs` | 220 | ~205 | single `record_rx_descriptor_telemetry` | per-descriptor (telemetry only) | **CLEAN** |
| `poll_descriptor/debug_log_throttle.rs` | 99 | ~85 | #4404 inc-1 extraction | cold debug | **CLEAN** (already peeled) |
| `poll_stages.rs` | 3,527 | **972** | 9 stage fns (L2 classify 166, GRE decap 27, parse+learn 37, fabric classify 27, `stage_screen_check` **316**, syn-cookie-ack 135, ipsec 71+57, flowless_l3 helper 55); 2,555 LOC inline `mod tests` (26 tests) | stage chain is hot; `stage_screen_check` on every non-cache-hit | **FINDING F2** (STATUS-UPDATE codex-171-3: prod only 972 LOC → 6-way split over-scoped; move tests) |
| `worker/mod.rs` | 1,625 | 1,556 | `BindingWorker` struct (already field-grouped via #959 into WorkerXskRings/Umem/TxPipeline/Cos/Scratch sub-structs) + `create`/bind/shared-umem-group/fallback lifecycle | struct is per-packet hot state | **D** (catalog D-class agy-171-23 confirmed — field-grouping done, further split → cache miss) |
| `worker/loop_body/mod.rs` | 1,776 | 1,430 | `worker_loop` (36–1337, **~1,300 LOC**): per-tick loop fusing telemetry publish, ArcSwap generation-refresh (~225 LOC), HA cmd apply, session reap, CoS status publish, delta drain AROUND one hot `poll_binding` call; + `reap_expired_sessions`, `count_local_session_expiries` | tick loop hot; cold blocks cadence-gated | **FINDING F3** (NEW: worker_loop uncataloged god-fn, cold fusion) |
| `shared_ops.rs` | 1,131 | 1,131 | 34 fns: HA shared-session-map ops (poison-recovery locks #2402, prewarm/promote/demote #4069, lookup-across-scopes, reverse-session synth, owner-RG index maint) | failover critical path (not per-packet) | **near-CLEAN** (cohesive around shared-session maps; sub-1500; `prewarm_reverse_synced_sessions_for_owner_rgs` 167 LOC is a cue but a cohesive failover routine) |
| `flow_cache.rs` | 1,000 | 997 | set-associative 4-way flow cache (FlowCacheStamp/Lookup/Entry/FlowCache, LRU promote/demote) + `const _: () = assert!` power-of-two/ways layout pins | **hot** (fast-path cache lookup) | **D / CLEAN** (cohesive data structure w/ compile-time layout pins) |
| `tests.rs` | 13,598 | — | 199 tests, flat (no sub-`mod`), spanning poll_descriptor orchestration, gre/nat/nat64/dnat, icmp/te/reject/embedded, flowless/frag, fabric/HA/shared_umem, filter, worker-binding; `txn_*` = differential full-pipeline golden-trace tests | test file (excluded from heatmap) | **FINDING F4** (INCREMENT codex-171-29: concrete cluster→module split plan) |
| `flow_cache_tests.rs` | 2,836 | — | flow-cache unit/differential tests | test | covered-by codex-171-29 (already a sibling `_tests.rs`) |

---

### A2-rust-fwd-frame

| File | wc -l | prod LOC | Responsibilities read | Hot-path proximity | Verdict |
|---|---|---|---|---|---|
| `forwarding/mod.rs` | 2822 | ~2820 | metadata-validate, canonical-table, neighbor-state classify, fabric-link build+redirect, NAT-scope, zone-pair, HA-resolution enforce/cache-validate, tunnel MSS, IPsec-admission, FIB v4/v6 lookup + ECMP, PBR route-override, local-delivery | **HOT** (FIB lookup + zone-pair + neighbor lookup on every session-miss / cache-validate) | **FINDING** — REFACTOR-tier genuine monolith; facade split warranted (F1,F2,F3) |
| `forwarding/host_inbound.rs` | 817 | ~534 | host-inbound-traffic token→L4-signature classify + admit | cold (config-build) + admit read on local-delivery | mostly clean; `classify_system_service` ~187-LOC match (minor, F9) |
| `forwarding_build/mod.rs` | 687 | ~610 | snapshot→ForwardingState build orchestrator | cold (config-apply) | **FINDING** — god-fn `build_..._and_previous` ~410 LOC (F4) |
| `forwarding_build/{cos,fib,interfaces,tunnels,zones,wg,validated}.rs` | 340–850 | — | per-domain populate_* helpers | cold | clean (already domain-split) |
| `forwarding_build/tests.rs` | 5042 | — | build tests | — | covered-by-catalog (test split; codex-171-29) |
| `forwarding/tests.rs` | 4632 | — | forwarding tests | — | covered-by-catalog (test split) |
| `frame/mod.rs` | 1710 | ~1699 | frame build / L2-rewrite / NAT-apply / inject / checksum-verify | **HOT** (per-packet byte mutation) | mostly **D** (hot cohesive); note (F9) |
| `frame/inspect.rs` | 1813 | ~1810 | L3/L4 offsets, fragment detect, term-match extract, ICMP-error suppression predicates, session-flow parse | **HOT** (parser) | **D-NEGATIVE** — parser locality CONFIRMED (F9) |
| `frame/wg.rs` | 1561 | ~608 | WG encap frame build + outer-MTU/source resolve + udp6 checksum | **HOT** (per WG-fwd packet) | FRESH; `wg_encap_frame` ~252-LOC hot god-fn = **D**; NOT a monolith by prod LOC (F9) |
| `frame/tcp_segmentation.rs` | 933 | ~378 | forwarded-TCP TSO segmentation | **HOT** | **STATUS-UPDATE** — cataloged dead branch already removed #4384 (F8) |
| `frame/{checksum,headers,tcp,generated,byte_writes}.rs` | 81–984 | — | checksum accum, outer-header serializers, TCP MSS, codegen | hot helpers | clean |
| `frame/build/*`, `frame/rewrite/*` | 371, 382 | — | per-family (v4/v6) build/rewrite codegen | hot | **D-NEGATIVE** — family codegen split CONFIRMED (codex-173-25) |
| `neighbor.rs` | 2036 | ~940 (4 inline test blocks) | monotonic clock, probe-socket select, ICMP-echo build, kernel ARP/NDP probe, warmer loop, NEWNEIGH build, kernel-neigh add, dyn-neigh mutate, netlink monitor thread, dump batch/initial, CPU pinning, MAC parse/format | mixed (probe trigger is worker-cold; monitor is its own thread) | **FINDING** — low cohesion + `neigh_monitor_thread` ~271-LOC god-fn (F5) |
| `neighbor_resolver.rs` | 1512 | ~800 | on-demand GET_NEIGH resolver thread + counters + NUD classify + rate-limit + action-decide | cold (resolver thread) | clean-ish (cohesive single subsystem, ~800 prod < 2000) |
| `neighbor_dispatch.rs` | 1399 | ~599 | pending-neigh admission/retry/learn, missing-neigh metadata | cold-sweep (off per-packet fast path) | FRESH; **FINDING** — `retry_pending_neigh` ~255-LOC god-fn (F6) |
| `umem/mod.rs` | 1345 | ~1342 | WorkerUmem mmap+pool lifecycle; `BindingLiveState` per-binding atomic aggregator + TX admission + session-delta | mixed: pool=cold, BindingLiveState=**HOT** (TX admission, heartbeat) | **D-NEGATIVE** — BindingLiveState D CONFIRMED; minor cold-pool file split note (F9) |
| `umem/{mmap,debug_state,profile,snapshot}.rs` | 30–357 | — | mmap syscall, debug-state tick, profile, snapshot | cold | clean |
| `types/forwarding.rs` | 1054 | ~1053 | `ForwardingState` god-struct + route/egress/tunnel/fabric types + ZoneHostInbound | hot (read per packet via ArcSwap) | **STATUS-UPDATE** — 64-field god-struct, GREW from cataloged 55 (F7) |
| `types/mod.rs` | 402 | ~257 | re-export hub + UserspaceDpMeta/ForwardPacketMeta (`#[repr(C)]`), SessionFlow, PacketDisposition | hot metadata | clean (cohesive) |
| `types/runtime.rs` | 503 | ~503 | worker-runtime structs/enums (BindingPlan, HAGroupRuntime, WorkerCommand, DebugPollCounters, contexts) | mixed | clean (cohesive collection < threshold) |
| `types/tx.rs` | 209 | ~209 | TX request/prepared/recycle types | hot | clean |

---

### A3-rust-cos-tx

| File | LOC | Responsibilities | Hot-path proximity | Verdict |
|---|---|---|---|---|
| `tx/dispatch/mod.rs` | 1,486 | `enqueue_pending_forwards` TX-drain orchestrator (270–1318, ~1,048 LOC) + 6 small helpers + `compute_forwarded_egress_ptb` (#4408 inc1) | **HOT** — per-forwarded-packet TX drain | INCREMENT(#4408) — god-fn still ~1,048 LOC; Phase-8 body next |
| `tx/dispatch/cos.rs` | 141 | CoS fast-path predicates for the drain (owner-live, shared-exact policy, local enqueue) | HOT helpers | D — cohesive, keep |
| `tx/dispatch/shared_recycle.rs` | 206 | Phase-10 cross-tick recycle routing + slot resolution | HOT (recycle) | D — cohesive, keep |
| `tx/dispatch/slow_path.rs` | 399 | build-failure reinject / `extract_l3_packet*`; all `#[cold]#[inline(never)]` | COLD (marked) | D — cohesive; `maybe_reinject_slow_path_from_frame` 171 LOC but cold |
| `tx/cos_classify.rs` | 1,335 | CoS TX-selection classify (cached + live), loss-priority/DSCP classifiers, enqueue-into-CoS | **HOT** — per-packet CoS classify | **NEW** — 2 god-fns (290/240 LOC), uncataloged, nearing WATCH |
| `tx/rings.rs` | 415 | single-owner/single-free UMEM frame lifecycle (reap/fill/wake) | **HOT** | D-NEGATIVE — confirmed D (codex-173-23), no action |
| `tx/drain/mod.rs` | 594 | TX pending-queue bound/drain/partition/ingest plumbing | HOT (drain) | D — cohesive; `ingest_cos_pending_tx_with_provenance` 184 LOC |
| `tx/transmit/mod.rs` (+stage/rewrite/write/verify/finalise) | 365+ | XSK transmit pipeline stages (already sub-split) | HOT | D — well-split, keep |
| `tx/tcp_segmentation.rs` | 309 | TSO segmentation into prepared/copy | HOT | D — cohesive |
| `cos/queue_service/mod.rs` | **2,058** | orchestrator (`drain_shaped_tx`) + RR selector + **waterfill selector (926–1357, ~432 LOC)** + surplus budgeting + settle/scratch + batch-build + submit shim | **HOT** — ns scheduler budget | INCREMENT(#4408) — **crossed 2,000 → REFACTOR-tier**; see F2 |
| `cos/queue_service/service.rs` | 718 | 4 exact-service fns (local/prepared × FIFO/flow-fair), each ~174 LOC | HOT | D — cohesive post-#1035-P3 split |
| `cos/queue_service/drain.rs` | 608 | scratch-build drain stage (FIFO + flow-fair, local/prepared) | HOT | D — cohesive; two 160–190 LOC drain fns |
| `cos/queue_service/submit_local.rs` / `submit_prepared.rs` | 194 / 177 | per-variant submit handlers | HOT | D — already split |
| `cos/queue_ops/{pop,push,v_min,accounting,active_buckets,drain,mod}.rs` | 294/506/280/188/110/107/408 | MQFQ bucket ops, v_min sync, active-set accounting | **HOT** | D — already decomposed; cohesive |
| `cos/tx_completion.rs` | 1,080 | timer-wheel park/wake/cascade, exact-backlog publish, apply-send-result | HOT (completion) | Watch — 2 apply fns ~113 LOC; below WATCH tier, cohesive |
| `cos/admission.rs` | 646 | flow-share/buffer/ECN admission | HOT | D — cohesive |
| `cos/token_bucket.rs` | 471 | root/queue lease top-up + refill | HOT | D — cohesive |
| `types/cos.rs` | 1,786 | **cold config types (~350 LOC) fused with** hot `CoSInterfaceRuntime`, `CoSQueueRuntime`(+sub-structs), `FlowFairState`, telemetry, timer-wheel | mixed hot/cold | D-NEGATIVE (FlowFairState) + **NEW** file-level config peel (F3) |
| `types/shared_cos_lease/lease.rs` | 1,460 | token-bucket + **v8 fair-share `acquire_v8_with_cause` (546–823, ~277 LOC god-fn)** + ~316 LOC of cold `v8_*` status getters + seqlock `snapshot_epoch_v8` | **HOT** — per-grant on TX admission | **NEW (uncataloged)** — god-fn + hot/cold fusion (F5) |
| `types/shared_cos_lease/{epoch,rotate_epoch_v8,publish_equal_flow_epoch_v8,vtime,backlog}.rs` | 565/446/247/238/210 | epoch state, rotation, equal-flow publish, vtime floor, backlog | HOT/cold mix | D — already split, cohesive |
| `cold_path_hist.rs` | 1,866 | TSC sampling + seqlock histogram publish/snapshot + slot map; **production ends ~L950, L952–1866 (~915 LOC) is inline `mod tests`** | HOT (sample) + cold (publish) | D-NEGATIVE (structs) + **NEW** test-colocation (F4) |
| `worker/cos/mod.rs` | 596 | build/reset/merge worker CoS fast-interfaces + owner-profile merges | cold (build) | D — cohesive |

Test mass noted (excluded from heatmap, flagged for review-cost, all
already `#[path]` siblings): `cos/queue_service/tests.rs` 4,384;
`tx/cos_classify_tests.rs` 4,617; `cos/queue_ops/pop_tests.rs` 2,060;
`cos/queue_ops/v_min_tests.rs` 1,992; `worker/cos/tests.rs` 2,708;
`types/shared_cos_lease/shared_cos_lease_tests.rs` 2,511;
`tx/dispatch/dispatch_tests.rs` 1,564. These are correctly colocated —
NOT findings. The one exception is `cold_path_hist.rs`, whose tests are
still INLINE (F4).

---

### A4-rust-session-policy

| File | LOC | Responsibilities | Hot-path proximity | Verdict |
|---|---|---|---|---|
| `policy.rs` | 3,598 | zone/book parse, AppCatalog, CompiledApplications, PolicyRuleCounter/Store, PolicyState, `parse_policy_state_with_counters` (558), evaluate family, frag-deny | HOT (`evaluate_policy_result_l3_aware` per new-flow + flowless) | **REFACTOR-tier**, INCREMENT #4421 — concrete map below |
| `policy_snapshot_error.rs` | 896 | one enum `SnapshotIntegrityError`, 19 cross-domain variants + Display (267-LOC `fmt`) | COLD (reconcile preflight) | Extraction CLEAN; keep single enum, do NOT sub-type. STATUS-UPDATE |
| `session/mod.rs` | 2,054 | `SessionTable` (25-field god-struct), `SessionEntry`, timeouts, per-IP limit, delta, account/update/touch | HOT (`account_packet`/`update_session`/`touch_if_stale` per packet) | REFACTOR-tier, INCREMENT #4421 — hot/cold map below; **no size_of pin exists** |
| `session/lookup.rs` | 411 | forward/reverse tuple read path, NAT/wire finders | HOT (per-packet) | `metadata.clone()` churn persists (×4). STATUS-UPDATE |
| `afxdp/session_glue/mod.rs` | 1,277 | forwarding-resolution lookups, worker-command apply, TCP-RST teardown, flow-cancel, shared-materialize, HA resolution | HOT (`resolve_flow_session_decision` per new flow) | LOW-COHESION grab-bag + 2 god-fns. **NEW** |
| `nat64.rs` | 2,527 | state/alloc, frag+ext-hdr walk, v6↔v4 write, ICMP-embedded, checksum, frame-build | HOT (`write_*_into`/`ipv6_l4_offset_and_protocol` per xlated pkt) | REFACTOR-tier, proposal VALIDATED; walker divergence FIXED. INCREMENT #4421 |
| `nat/source.rs` | 1,389 | SNAT rule parse, scope/l4 match, `match_source_nat_result_for_tuple` (342), release/reserve, nat64-pool port | HOT (new-flow SNAT) | 342-LOC hot god-fn. **NEW detail** / INCREMENT #4409 |
| `nat/allocator.rs` | 1,163 | `PortAllocator` (Shared+LiveState split), `allocate_translation` (124), GC-under-lock, deterministic v4 | HOT (`allocate_translation` under `Mutex`) | GC-under-Mutex confirmed; alloc god-fn peeled. STATUS-UPDATE #4409 |
| `nat/destination.rs` | 1,088 | `DnatTable`/`DnatEntry`, LPM+slot match, `from_snapshots` (234), `lookup_with_counter_scoped` (139) | HOT (DNAT lookup) but single-domain | Cohesive single-domain (DNAT). D / low-B. **Fresh** |
| `nat/mod.rs` | 297 | `NatScopeCtx`, `NatDecision`, `NatRuleCounter`/Store | mixed | Fine, D-NEGATIVE |
| `screen/mod.rs` | 1,540 | `ScreenState`, profile mgmt, `check_packet_with_zone_id_opts` (~330), flowless, cleanup, syn-cookie sub-state | HOT (per first-packet) | D-class PARTIALLY STALE — inline ~330-LOC check fn. **NEW/D-correction** |
| `screen/scan.rs` | 1,213 | generic `ScanCore<T>`, PortScan/IpSweep trackers, ~620 LOC inline tests | HOT (new-flow scan) | Cohesive generic; test-heavy. D-NEGATIVE + test note. **Fresh** |
| `screen/extract.rs` | 400 | one fn `extract_screen_info` (348) | HOT (per screened pkt) | Single god-fn = whole file. INCREMENT codex-171-8 |
| `slowpath.rs` | 1,659 | reinjector, rate-limiter, worker, sync/nonblocking/io_uring write, tun/sysctl; ~740 LOC inline tests | slow path (TUN reinject) | Prod ~918 LOC; WATCH is test-inflated; io_uring invariants intact. STATUS-UPDATE |
| `filter/compiler.rs` | ~1,065 | `parse_filter_state*`, `parse_term` (426), policer lowering, matchers | COLD (compile) | 426-LOC `parse_term`. INCREMENT agy-171-17 |
| `filter/engine/eval.rs` | 1,026 | first-match evaluators, all `#[inline]` | HOT (per-packet) | Well-decomposed (engine/ split). D-NEGATIVE |
| `filter/policer.rs` | ~485 | srTCM/trTCM meter core | HOT (metered) | Small, cohesive. D-NEGATIVE |
| `filter/mod.rs` (SmallVec) | — | `CachedThreeColorPolicers` = `SmallVec<[_;2]>` | built cold, replay hot | Cap smell FIXED (#4566). STATUS-UPDATE |
| Test files | see F17 | `policy_tests.rs` 7,161 / `session/tests.rs` 6,994 / `screen/tests.rs` 5,395 / `nat64_tests.rs` 3,984 / `filter/tests.rs` 8,330 / `session_glue/tests.rs` 5,587 | n/a | Open test-splits; concrete mapping in F17 |

---

### A5-rust-control

| Path | LOC | Responsibilities | Hot-path proximity | Verdict |
|---|---|---|---|---|
| `event_stream/codec.rs` | 1165 | RT_FLOW/HA wire codec: 4 encoders + decoder over a 152-byte payload; 69 bare `base+<lit>` offset writes, **0 named offset consts** | cold (per-event emit, not per-pkt) but wire-correctness critical | **NEW A5-F1** (B) — offset-literal SSOT + 196-LOC encoder god-fn |
| `afxdp/coordinator/status.rs` | 1195 | Operator-status projection impl on Coordinator: ~30 read methods building `protocol::*Status` | cold (status poll 1/s) | **NEW A5-F2** (A) — 201-LOC `worker_runtime_snapshots` god-fn + projection grab-bag |
| `protocol/binding.rs` | 1168 | Wire SSOT: 7 status DTOs, dominated by `BindingStatus` (~539 LOC of serde fields) + `From<&BindingStatus>` (188) | decode boundary (cold) | **NEW A5-F3** D-NEGATIVE — one cohesive schema; already #1325-split |
| `protocol/control.rs` | 1040 | Wire SSOT: 15 control DTOs, dominated by `ProcessStatus` (~491 LOC) + version consts | decode boundary (cold) | D-NEGATIVE (folds into A5-F3) |
| `xsk_ffi.rs` | 1462 | AF_XDP FFI wrapper: Umem/Socket/DeviceQueue/4 ring types, 72 unsafe sites | HOT (WriteTx/WriteFill producer rings, #2383) | **NEW A5-F4** D-NEGATIVE — cohesive per-type FFI; unsafe surface small per impl |
| `state_writer.rs` | 1280 | Atomic state-file writer (io_uring→sync fallback, PID-orphan sweep) | cold (state export) | **NEW A5-F5** D-NEGATIVE — prod code well-factored (largest prod fn 63); size is inline tests |
| `userspace-xdp/src/lib.rs` | 1541 | `#![no_std] #![no_main]` eBPF XDP shim: `try_xdp_userspace` 342 + parse helpers | kernel dataplane (verifier-bounded) | **NEW A5-F6** D-NEGATIVE — verifier constraints force shape; split needs tail-calls |
| `afxdp/coordinator/mod.rs` | 948 | Coordinator root: lifecycle (`stop_inner` 161), `queue_warm_pass` 167, neighbor apply 54, debug summaries 120+107 | cold (control/reconcile) | **NEW A5-F7** LOW — below threshold, cohesive; optional debug-summary peel |
| `afxdp/coordinator/tunnel_supervision.rs` | 960 | Spawn/reconcile/prune/liveness/tombstone for local-tunnel sources AND wg-control threads (two parallel lifecycles) | cold (config-apply) | **NEW A5-F8** LOW — near-duplicate lifecycles, DRY candidate |
| `afxdp/coordinator/cos_leases.rs` | 838 | CoS runtime-map/lease refresh; `aggregate_cos_statuses_across_workers` 219 | cold (reconcile/status), shared_cos_lease perf-adjacent | STATUS-UPDATE (adjacent #4408) — 219-LOC aggregator noted |
| `afxdp/coordinator/wg_control.rs` | 2280 | WG control thread: loop/attempt-machine/inbound-dispatch/socket-cmsg/encap-send | cold (handshake/keepalive control, NOT per-pkt encap) | STATUS-UPDATE codex-173-17 — no increment; god-fns confirmed |
| `afxdp/wg/engine.rs` | 1805 | WG transport (hot encap/decap) + peer reconcile (cold) | **HOT** (`try_decap`/`encap_inner` per-pkt crypto) | STATUS-UPDATE agy-171-20/codex-171-9 + NEW boundary detail (B) |
| `afxdp/wg/cookie.rs` | 1435 | WG cookie responder + rate-limit + initiator; large inline test block | cold (cookie replies under load) | STATUS-UPDATE codex-171-18 — no god-fn; WATCH-tier |
| `event_stream/mod.rs` | 1693 | EventStreamSender: io-thread/connected-loop/replay/control-frames/drain + clock anchoring + RT_FLOW session emitters | slow-path telemetry I/O (bounded backpressure) | STATUS-UPDATE codex-173-15 + NEW detail (B) |
| `afxdp/event_emit.rs` | 1492 | 5 `emit_*` cold-path event builders (policy/host-inbound/screen/filter) + app-id resolve + big inline test block | cold (per deny/drop/log, not per-pkt) | STATUS-UPDATE codex-173-12 — well-factored; low-value split |
| `server/helpers.rs` | 1292 | `refresh_status` 312 + queue planning (`replan_queues`/plan-key) + HA `build_synced_session_entry` 193 + nat64 reverse rebuild | cold (control-socket apply/status) | INCREMENT codex-171-10 — file broader than refresh_status alone |
| `server/lifecycle.rs` | 732 | `run()` entry, argv/socket setup, sysctl raise-only, signal handling | cold (startup) | D-NEGATIVE — below threshold, cohesive |
| `afxdp/coordinator/tests.rs` | 4005 | colocated coordinator tests | test | test-split (codex-171-29) — noted below |
| `afxdp/wg/tests.rs` | 3909 | colocated wg tests | test | test-split (codex-171-29) — noted below |

---

### A6-go-config

| Path | LOC | Responsibilities | Verdict |
|---|---|---|---|
| compiler_uniformgates.go | 1,659 | ONE fn `runUniformGates` running ~78 ordered fail-open gates | **FINDING F1 (NEW)** — single-fn monolith; order-pinned |
| compiler_validate_warn.go | 3,330 | `ValidateConfig` (~1,534 LOC) + ~35 warn helpers | **FINDING F2 (INCREMENT codex-171-20)** — measured carve |
| compiler.go | 2,110 | `compileOpts` struct (1,509 LOC/98 fields) + 8 fns; `compileExpanded` now 124 LOC | **FINDING F3 (STATUS-UPDATE + INCREMENT F-044)** |
| compiler_nat.go | 2,529 | 37 fns; compileNATSource(521)/Destination(227)/Static(171) + strict validators + multi-value helpers | **FINDING F5** — 4-file seam validated (covered-by-catalog + detail) |
| compiler_protocols.go | 1,180 | `compileProtocols` 783-LOC god-fn (LLDP/OSPF/BGP/ISIS/RIP/RA) + parsers | **FINDING F4 (NEW)** — uncataloged god-fn |
| compiler_system.go | 1,881 | `compileSystem`(536) + `compileChassis`(300) + 26 helpers | **FINDING F6** — covered-by-catalog (codex-171-22); fn-level detail |
| compiler_services.go | 1,821 | 27 compile* helpers, largest compileDHCPRelay(149) — no >150 god-fn | covered-by-catalog (codex-171-23); already fn-decomposed |
| compiler_interfaces.go | 1,279 | `compileInterfaces` 535-LOC god-fn + parseVRRPGroups(237) | **FINDING F6 (NEW)** — uncataloged god-fn |
| compiler_class_of_service.go | 1,205 | `compileClassOfService` 509-LOC god-fn + CoS parsers | **FINDING F6 (NEW)** — uncataloged god-fn |
| compiler_firewall.go | 1,206 | `compileFirewall`(319) + `compileFilterFrom`(222) + family-collision AST validators | **FINDING F6 (NEW)** — uncataloged god-fns |
| compiler_routing.go | 1,226 | compileStaticRoutes(222)/parsePolicyTermInlineKeys(171)/compilePolicyOptions(160) | mid-band; god-fns noted (F6 list) |
| compiler_validate_strict_filter.go | 1,660 | 28 firewall-filter strict validators, largest 142 LOC | covered-by-catalog (strict split FIXED); residual note |
| compiler_validate_strict_policy.go | 1,009 | 17 policy strict validators, largest 137 LOC | covered-by-catalog (strict split FIXED); clean |
| types_system.go | 1,544 | 64 typed-config struct decls (SNMP/syslog/login/RPM/NetFlow/DDNS/DHCP/fwd-opts) | **D-NEGATIVE** — declarative, biggest struct ~49 LOC |
| types_security.go | 1,202 | 64 typed-config struct decls (scheduler/feeds/flow/log/zone/policy/NAT/screen) | **D-NEGATIVE** — declarative, no god-struct |
| types_routing.go | 642 | routing typed structs | clean |
| schema_security.go | 1,255 | `var schemaSecurity`(1,073-LOC literal) + `var schemaApplications` + 3 builders | **D-NEGATIVE** — declarative schemaNode table (SSOT) |
| schema_system.go | 1,021 | `var schemaSystem/schemaServices/schemaSNMP/schemaEventOptions` + DHCP/DDNS builders | **D-NEGATIVE** — declarative table (SSOT) |
| schema.go | 261 | schemaNode type + isTypedLeaf/isScalarValueLeaf + init | clean |
| schema_walk.go | 803 | SchemaValidate + 20 walk/validate helpers (incl validateMultiValueLeaf #2419) | clean |
| schema_complete.go | 353 | CompleteSetPath(WithValues) completion helpers | clean |
| schema_validators.go | 186 (+9 siblings) | scalar/enum/int/percent validators | **STATUS-UPDATE** — codex-173-1 split DONE (10 files) |
| schema_interfaces/cos/routing.go | 530/537/801 | declarative schema tables | D-class table |
| compiler_security.go | 96 (+7 domain files) | thin dispatch | **STATUS-UPDATE** — fable-163 F28 grab-bag SPLIT |
| parser.go | 361 | lexer/AST core, 11 fns | **D-NEGATIVE** — clean, no monolith |
| compiler_ipsec.go | 681 | IPsec compile | clean |
| compiler_applications.go | 732 | application compile | clean |
| parser_security_test.go | 5,805 | 114 test fns across IPsec/fw/policy/screen/NAT/route | **FINDING F7** — test-file split |
| parser_ast_test.go | 5,586 | 122 test fns (dual-AST) | test-file split candidate |
| parser_routing_test.go | 3,936 | 96 test fns | test-file split candidate |
| parser_class_of_service_test.go | 2,097 | 48 test fns | mid-band test file |

Coverage-proof god-function sweep (`awk` fn-LOC over all mid-band compile* files, threshold 150 LOC):
compileProtocols 783 · compileSystem 536 · compileInterfaces 535 · compileNATSource 521 ·
compileClassOfService 509 · compileFirewall 319 · compileChassis 300 · validateNATHostMaskStrict 249 ·
parseVRRPGroups 237 · validateNPTv6Strict 234 · compileNATDestination 227 · compileStaticRoutes 222 ·
compileFilterFrom 222 · validateFirewallFilterFamilyAnyMatchesAST 185 · parsePolicyTermInlineKeys 171 ·
compileNATStatic 171 · compilePolicyOptions 160 · validateFirewallFilterFamilyCollisionsAST 160.
No uncataloged god-function escaped the file list.

---

### A7-go-dpmgr

| Path | LOC | Responsibilities | Verdict |
|---|---|---|---|
| userspace/protocol.go | 2,979 | 77 wire-mirror structs (Go side of Rust `protocol/` SSOT); 2 methods only (ProcessStatus Marshal/UnmarshalJSON) — pure DTO file, **no struct-vs-builder fusion** | Cataloged (codex-171-11). STATUS-UPDATE: split is **A-class mechanical** (same package). |
| userspace/maps_sync.go | 1,763 | 36 fns; god-fn `applyHelperStatusLocked` L343-826 (**483 LOC**) holds `Manager.mu`: cpumap preserve → stale-session flush → ctrl mode/strict → classifier → ingress/local/NAT-addr maps → bindings verify → **counter bridge** (calls `syncBPFCountersLocked` L782). Plus builders (`buildLocalAddressEntries`, `buildUserspaceIngress*`, native-endian `pickInterfaceSnapshotV4/V6`). | Cataloged (codex-171-12). INCREMENT: exact fn map + fail-closed/`m.mu` boundaries below. |
| userspace/manager_ha.go | 1,425 | **THREE fused domains**: (a) HA RG state+watchdog L22-711, (b) BPF counter/flow-stat bridge L711-848 (`sumBindingCounters`/`syncBPFCountersLocked`), (c) session-sync + native-endian helpers L849-1462. | NEW (beyond dead-counter): 3-responsibility split. Dead-counter opus-172 H-4 = STATUS-UPDATE (partly fixed). |
| userspace/eventstream.go | 1,169 | 40 fns: transport (accept/read/write/ack loops), dispatch/queue, pending-frame ring, decode, dp-event counters | Cataloged (codex-171-13). STATUS-UPDATE: seam validated, still open. |
| userspace/format/status.go | 1,073 | Status/CoS/flow formatting; god-fn `FormatStatusSummary` L103-713 (**610 LOC**) | NEW: A-class formatter god-fn (clean split by section). |
| userspace/manager.go | 421 | Accessors + lifecycle delegates only | Clean — **template** for other splits (matches dedup §1a FIXED). |
| dataplane/compiler.go | 1,733 | retained-shim config compiler: addrbook/apps/policies/flow + **ethtool/NIC tuning** + MAC/iface resolution. `compilePolicies` L744-1040 (**296 LOC**) | NEW (fresh): domain-split + ethtool peel. |
| dataplane/compiler_iface.go | 1,394 | god-fn `compileZones` L249-1180 (**931 LOC**) fuses zones + networkd file-gen + fabric bonds + bridge domains + unmanaged bring-down (device-map skip) | **NEW (fresh) — largest single finding.** |
| dataplane/compiler_nat.go | 1,258 | god-fn `compileNAT` L159-886 (**727 LOC**): SNAT pools+rules / DNAT / stale-delete. Distinct from pkg/config/compiler_nat.go | NEW (fresh). |
| dataplane/loader.go | 1,207 | Manager XDP attach/detach + eBPF map/prog accessors + **55 no-op** `userspaceShimCompileDataplane` stub methods (L349-447) | Borderline; largest fn <110 LOC. Low-priority A-class (extract stub adapter). |
| dataplane/types.go | 1,056 | 51 BPF-mirror structs + consts, **1 func**. Every struct carries `Pad`/`sizeof` C/Go alignment invariant | NEW-ish (fresh): domain-split possible but **guardrail-heavy** (struct-mirror). |
| dataplane/loader_userspace_shim.go | 469 | shim load/attach | Clean. |
| dataplane/dataplane.go | 459 | retirement sentinels (`ErrEBPFBackendRetired`) | D — cohesive. |
| userspace/manager_test.go | 6,782 | **164 test fns**, 68 `Build*` cluster | NEW: concrete split plan below. |
| dataplane/retirement_boundary_canary_test.go | 3,354 | 26 fns; go/ast boundary-gate + import allowlist (#1373) | **D-NEGATIVE** — deliberate single-purpose CI canary. |

---

### A8-go-daemon-ha

**pkg/daemon**

- `daemon_run.go` — 2,329 LOC, 11 funcs. **`Run` is 1,692 LOC** (L175–1866): the
  entire daemon lifecycle — ~25 subsystem constructions, ~13 goroutine spawns,
  boot-class classification, bootstrap gating, forwarding enable, HA wiring, AND
  the full shutdown teardown (L1697–1866). Also `inferIPv6StaticNextHopInterfaces`
  272-LOC pure helper. **Verdict: MONOLITH god-function (NEW, highest value).**
- `daemon_apply.go` — 1,926 LOC, 25 funcs. **`applyConfigLocked` 919 LOC**
  (was 1,148 when #4407 filed) + `applyTailReconciles` 273 LOC (already peeled,
  #4407 Phase A). **Verdict: cataloged #4407 open — STATUS-UPDATE + seam detail.**
- `daemon_ha.go` — 1,483 LOC, 39 funcs. `reconcileRGState` 250, `watchClusterEvents`
  182, `warmNeighborCache` 80, `applyRethServicesForRG` 94. **Verdict: two large
  god-fns; file is domain-cohesive (RG state machine + event fan-out).**
- `daemon_ha_userspace.go` — 1,123 LOC, 43 funcs. Largest fn 85 (delta→session
  decode v4/v6 pair). **Verdict: cohesive (userspace session-delta translation);
  many small fns; v4/v6 duplication only.**
- `daemon_ha_sync.go` — 1,013 LOC, 21 funcs. **`startClusterComms` 466 LOC** —
  HA wiring god-function. `startSessionSyncPrimeRetry` 102. **Verdict: NEW
  god-function.**
- `daemon_ha_fabric.go` — 965 LOC, 23 funcs. `refreshFabricFwd` 162,
  `refreshFabricFwd1` 100 (fwd0/fwd1 near-duplicate pair). **Verdict: cohesive
  (fabric cross-chassis fwd); fwd0/fwd1 duplication is the smell, not size.**
- `daemon_nft.go` — 1,432 LOC, 30 funcs. **`nftRulesFromTerm` 311 LOC** +
  `buildHostInboundFilterPayload` 114 + `applyHostInboundFilter` 109. **Verdict:
  cohesive (nft table generation) but one 311-LOC term-lowering god-fn (NEW).**
- `daemon_system.go` — 1,310 LOC, 23 funcs. `applySyslogConfig` 157,
  `applySystemLogin` 130, `applySSHConfig` 129, `reconcileUserPassword` 100,
  `applySyslogFiles` 95. **Verdict: low-cohesion grab-bag (syslog + timezone +
  login + ssh + password), splittable by domain (NEW, medium).**
- `bootstrap.go` — 931 LOC, 27 funcs. `enterBootstrapMode` 123, `setupBootstrapLifeline`
  75, `computeBootClass` 60. **Verdict: cohesive (SAFE-BOOTSTRAP state machine),
  no god-fn; keep.**
- `device_map.go` — 695 LOC, 24 funcs. Both rename sites route through the single
  `applyStartupNamingPolicy` (L82); `deviceMapCommitPreflight` 65. **Verdict:
  D-NEGATIVE — well-factored, #1956 dual-branch invariant consolidated.**
- `linksetup.go` — 545 LOC. Cohesive startup interface naming. **Verdict: fine.**

**pkg/cluster**

- `sync_conn.go` — 1,858 LOC, 55 funcs (49 SessionSync methods). **`handleMessage`
  346-LOC / ~27-case dispatch** + `handleDisconnect` 142 + `syncSweep` 116 +
  `handleNewConnection` 86 + `receiveLoop` 82 + generation-guard cluster
  (`nextInstallGen`/`takeDeleteGen*`/`recvGen` tombstone). **Verdict:
  PRIOR-CAMPAIGN (grew ~1,515→1,858) — STATUS-UPDATE + NEW dispatch/genguard seam.**
- `sync.go` — 998 LOC, 35 funcs. `TransferReadinessSnapshot.Reason` 246 (string
  builder). **Verdict: watch; Reason() is a formatting fn, low risk.**
- `heartbeat.go` — 881 LOC. `UnmarshalHeartbeat` 120, `marshalHeartbeatBody` 87,
  `readLoop` 86. **Verdict: cohesive (wire + auth + recv), keep.**
- `failover.go` — 876 LOC, 24 funcs. 4 fns ~80–102 (Manual/RequestPeer × single/batch).
  **Verdict: D-NEGATIVE (codex-171-32) — confirm one `m.mu` domain.**
- `sync_protocol.go` — 829 LOC. 4 encode/decode fns 92–123 (session v4/v6).
  **Verdict: cohesive codec; v4/v6 mechanical duplication only.**
- `garp.go` — 754 LOC. `SendGratuitousARPBurstGated` 74. **Verdict: cohesive.**
- `status.go` — 691 LOC, **only 8 funcs**. `FormatInformation` 263,
  `FormatInterfaces` 117, `FormatIPMonitoringStatus`/`FormatStatus` 88.
  **Verdict: formatting dumping-ground (NEW, low-medium).**
- `sync_failover.go` 607 · `monitor.go` 597 (`probeICMP` 116) · `heartbeat_manager.go`
  492 · `election.go` 475. **Verdict: all cohesive, sub-threshold.**

**pkg/vrrp**

- `instance.go` — 2,417 LOC, 64 funcs (real max fn ~139; the 179 "String" count is
  an artifact of type decls between funcs). `stepBackup` 139, `run` 121,
  `receiverIPv6` 112, `receiver` 91. **Verdict: cataloged codex-171-27 —
  INCREMENT (validate 6-file seam + gate preservation).**
- `manager.go` — 1,108 LOC, 29 funcs. `UpdateInstances` 209, `openAfPacketReceiver`
  154. **Verdict: NEW — `UpdateInstances` diff/lifecycle god-fn.**
- `track.go` 341 · `packet.go` 277 · `addrwatch.go` 219 · `vrrp.go` 266.
  **Verdict: all cohesive, fine (the seam targets from the README already).**

**pkg/conntrack**

- `gc.go` — 554 LOC, 12 funcs. **`sweep` 283 LOC** — skip/snapshot/fastpath/
  v4-iterate+expire+count/v4-callbacks/v6-iterate+expire+count/v6-callbacks/
  persistent-NAT-GC/push-counts/watermark-hysteresis. **Verdict: NEW — one large
  sweep fn with v4/v6 duplication; HA-callback + gc.mu ordering is preservation-
  critical.**

**pkg/ra**

- `sender.go` — 990 LOC, 30 funcs. `buildRA` 175, `run` 93. **Verdict: NEW —
  `buildRA` option-assembly fn; medium.**
- `ra.go` — 880 LOC. `Apply` 152, `configEqual` 72. **Verdict: cohesive
  (draining-tombstone manager); `Apply` is the state machine, keep co-located.**
- `serialize_test.go` 2,648 · test colocation note below.

---

### A9-go-api-cli

**pkg/api**

| File | LOC | Responsibilities | Verdict |
|---|---|---|---|
| metrics_descriptors.go | 1,896 | ONE fn `newCollector` builds every `prometheus.Desc` | **God-fn (F1)** — cataloged codex-171-15; measured 1,886-LOC single fn |
| metrics_userspace.go | 1,819 | 1 dispatcher + ~40 per-domain `emit*` emitters | Already fn-decomposed; single-`Status()` invariant holds → STATUS-UPDATE (F2) |
| sessions.go | 1,291 | REST session list/cursor/summary/clear + `sessionEntryV4/V6`, `matchV4/V6`, pageToken codec | **Cross-surface dup (F3)** copy #1 of 3 |
| metrics.go | 1,040 | `Describe`(288)/`Collect`(151) + histogram helpers | Big but split by role; (A) tail-carve only — no finding |
| security.go | 801 | zones/policies/screen/events/match-policies REST handlers; `policiesHandler`(260), `matchPoliciesHandler`(277) | Two large handlers; secondary (F8) |
| types.go | 790 | REST DTO struct decls | Declarative — D |
| server.go | 715 | Server struct(38 fields) + Run + self-signed cert gen | Cohesive lifecycle — no finding |
| show_text.go | 312 | `showTextHandler`: REST-local text render for 12 topics | **Dup renderer (F4)** vs gRPC ShowText |
| metrics_counters.go / system.go / nat.go / interfaces.go / config.go / sse.go … | <500 | per-domain REST handlers | OK |

**pkg/grpcapi**

| File | LOC | Responsibilities | Verdict |
|---|---|---|---|
| server_diag.go | 1,602 | Ping/Traceroute/MonitorPacketDrop/MonitorInterface (live diag streams) + SystemAction(413/18-case) + zeroize (login-account wipe, UID lookup, rendered-config erase) | **Low-cohesion dumping ground + god-fn (F5)** — NOT cataloged |
| server_sessions.go | 1,408 | gRPC session RPCs + `getSessionsCursor`(180), `ClearSessions`(177) + `sessionEntryV4/V6`, `matchV4/V6`, pageToken codec | **Cross-surface dup (F3)** copy #2 of 3 |
| server_show_security_text.go | 1,063 | ~22 `show*` text renderers (ipsec/screen/ike/wg/alg/…) | Already one-fn-per-topic; (A) file-carve — minor |
| server_show_interfaces.go | 935 | `ShowInterfacesDetail`(348) + `showInterfacesTerse`(359) god-fns + reth helpers | **God-fns + reth dup (F6)** |
| server_cluster.go | 828 | cluster RPCs | OK |
| server.go | 481 | Server god-struct (56-line/~40-field, 13 `*Fn` closures) + interceptors | Minor struct observation (F9) |
| server_show.go | 538 | `ShowText` topic dispatcher (prefix + switch) | Dispatch, cohesive; feeds F4 |
| 28 production server_*.go total | — | one RPC-domain per file | Service is WELL-decomposed by file — NOT a god-service |

**pkg/cli**

| File | LOC | Responsibilities | Verdict |
|---|---|---|---|
| cli_show_interfaces.go | 1,396 | `showInterfaces`(411), `showInterfacesTerse`(308), `showInterfacesDetail`(152) + reth helpers | **God-fns + reth dup (F6)** |
| cli_request.go | 1,328 | ping/traceroute/test/monitor + `handleRequest*` chassis/dhcp/protocols/system/security | Many small handlers; (A) carve `request_{diag,test,chassis,system,security}.go` — minor |
| cli_show_flow.go | 1,243 | `showFlowSession`(542) god-fn + top-talkers/timeouts/stats | **God-fn + cross-surface dup (F7)** copy #3 of 3 |
| cli_show_routing.go | 1,131 | 25 `show{Route,OSPF,BGP,ISIS,BFD,VRRP,ARP,...}` fns | One-fn-per-proto; (A) carve — minor |
| cli_show_system.go | 1,055 | 18 `showSystem*` fns | One-fn-per-topic; (A) carve — minor |
| monitor.go | 949 | trace-file rotation + monitor-security-flow FSM | Cohesive stream tooling — no finding |
| session_filter.go | 424 | `sessionFilter` type + `matchesV4/V6`/`ifaceMatches`/`resolveEgressIface` | **Cross-surface dup (F3)** filter copy #3 |
| cli.go | 540 | CLI struct + ~30 `Set*` DI wiring + Run loop | DI wiring, cohesive — no finding |
| completion.go | 577 | readline completer adapter | OK |

**cmd/cli**

| File | LOC | Responsibilities | Verdict |
|---|---|---|---|
| show.go | 2,100 | `handleShow`(326 nested-switch dispatch) + ~45 thin `show*`/`handleShow*` that mostly proxy gRPC | **Cataloged per-command split (F10)**; dispatch is the one real god-fn |
| shared.go | 610 | ctl helpers | OK |
| main.go | 551 | arg routing | OK |

**pkg/cmdtree**

| File | LOC | Responsibilities | Verdict |
|---|---|---|---|
| tree.go | 1,548 | `var OperationalTree`/`ConfigTree` declarative maps (~1,000 LOC) + completion/help/dynamic-value fns (tail ~400 LOC) | **D-class correction (F11)** — bulk is a declarative table, not a god-fn |

---

### A10-go-services

| File | LOC | Responsibilities | Verdict |
|---|---|---|---|
| pkg/frr/policy_render.go | 1,938 | route-map/route-filter/policy-options/protocol/bfd render | **INCREMENT** (cataloged codex-173-18); NEW god-fn detail: `renderRouteMapForPolicy` 406 LOC |
| pkg/frr/manager.go | 911 | FRR lifecycle, executor, managed-section assembly | (B) split candidate, below threshold; `executor` 149, `buildManagedSection` 114 — note only |
| pkg/frr/config_render.go | 394 | interface/router-id/static render | cohesive; no action |
| pkg/frr/status_parse.go | 468 | vtysh JSON parse | cohesive; no action |
| pkg/frr/frr_test.go | 5,920 | test mega-file | **INCREMENT** — split per production seam (see finding F-FRRTEST) |
| pkg/routing/tunnel.go | 1,877 | plan-diff + netlink + exec + keepalive engine under one `t.mu` | **INCREMENT / class C** (cataloged codex-173-8); lock-scope narrowing detail below |
| pkg/routing/rules.go | 1,274 | nextTable + ribGroup + PBR (3 domains) | **STATUS-UPDATE** (cataloged codex-156); still fused, unsplit |
| pkg/routing/vrf.go | 361 | VRF device mgmt | cohesive; no action |
| pkg/routing/routes.go | 313 | route install | cohesive; no action |
| pkg/routing/xfrmi.go / xfrm.go | 232 | XFRM iface (dead-guard noted ps-038) | no NEW action |
| pkg/dhcp/dhcp.go | 1,800 | v4+v6 client FSM, lease parse, address, PD | **STATUS-UPDATE** (cataloged codex-173-11); v4/v6 `lease_fsm` seam validated below |
| pkg/dhcprelay/relay.go | 1,545 | relay mgr + session loop + L2 + option82 | **INCREMENT** (cataloged codex-173-20); NEW god-fn: `runRelaySession` 343 LOC |
| pkg/dhcpserver/dhcpserver.go | 1,040 | Kea v4/v6 config-gen + unit lifecycle | **NEW** (uncataloged) — moderate; below 1500 but two 120+-LOC gen fns |
| pkg/ipsec/policy.go | 1,059 | swanctl render (god-fn) + PrepareConfig + family resolve | **STATUS-UPDATE + NEW god-fn** (prior ~880→1,059, GREW); `renderConfig` 272 LOC |
| pkg/ipsec/ike.go | 890 | IKE gateway/proposal compile | (B) split candidate; note only |
| pkg/snmp/agent.go | 1,519 | BER + OID table + ifTable + PDU dispatch + trap queue | **STATUS-UPDATE** (cataloged codex-173-19); 57 fns, no single god-fn — Class A |
| pkg/snmp/v3.go | 1,084 | USM key-deriv + auth-HMAC + privacy-crypto + PDU build | **NEW** (uncataloged) — crypto/PDU fusion confirmed |
| pkg/ddns/surface_a.go | 1,957 | Surface-A scope FSM: reconcile/publish/withdraw/orphan/status | **STATUS-UPDATE** (cataloged codex-171-28); file-split NOT landed; field-grouping NOT done |
| pkg/ddns/manager.go | 1,359 | lease-DDNS reconcile + policy compile + upsert/delete | **NEW** (uncataloged) — 74-line Manager struct; `policyFromConfig` 167, `ReconcileScoped` 144 |
| pkg/ddns/backend_rfc2136.go | 1,100 | RFC2136 TSIG DNS UPDATE backend | **NEW** (uncataloged) — cohesive-ish protocol backend; low severity |
| pkg/logging/ringbuf.go | 1,369 | decode + enrich + callback/syslog/local fanout | **NEW** (uncataloged) — `EventReader` god-struct (8 RWMutex domains) |
| pkg/logging/syslog.go | 769 | syslog transport | cohesive; no action |
| pkg/policymatch/policymatch.go | 1,679 | selector/query/match/app/route-drop/render | **STATUS-UPDATE** (cataloged codex-171-21); `SelectorArgs.Query` 192, `ValidateProtocol` 173, `Match` 162 |
| pkg/eventengine/engine.go | 1,259 | runtime-set/matcher/planner/action-queue/worker | **STATUS-UPDATE** (cataloged codex-173-9); no single god-fn (largest 91) |
| pkg/flowexport/ipfix.go | 1,075 | IPFIX template + field + exporter | **D-NEGATIVE (file)** — cohesive encoder; package-monolith note stands (STATUS-UPDATE codex-158) |
| pkg/flowexport/manager.go / netflow.go | 889 / 815 | collector mgr / v9 encoder | package-level split note only |
| pkg/ipmon/ipmon.go | 1,016 | policy FSM + overlay + actuator + status | **STATUS-UPDATE** (cataloged codex-173-10); `run` 95 largest |
| pkg/upgrade/cutover.go | 953 | A/B cutover orchestration | **NEW** (uncataloged) — `Run` **431-LOC** god-fn |
| pkg/monitoriface/monitor.go | 952 | snapshot aggregate + terse/detail render | **NEW** (uncataloged) — `RenderSingleInterface` 178 LOC |
| pkg/networkd/networkd.go | 674 | .link/.network gen | below threshold; no action |
| pkg/configstore/store_commit.go | 828 | commit/rollback state | **STATUS-UPDATE** (cataloged codex-173-2); durability-ordering guarded — do not disturb |
| pkg/configstore/store.go | 603 | candidate/active store | STATUS-UPDATE only |

---

**Coverage proof (god-function sweep, this module group)**

Every production file ≥600 LOC in the group was `grep -n '^func '`-swept and every function ≥60 LOC span-verified. God-functions found (>150 LOC): `cutover.go Run` 431 (NEW), `policy_render.go renderRouteMapForPolicy` 406 (INCREMENT), `relay.go runRelaySession` 343 (INCREMENT), `ipsec/policy.go renderConfig` 272 (STATUS+detail), `surface_a.go publishLocked` 196 / `reconcileScopeLocked` 167 (STATUS), `policymatch Query` 192 / `ValidateProtocol` 173 (STATUS), `frr renderRouteFilterEntry` 173 (INCREMENT), `dhcp runDHCPv4` 179 / `runDHCPv6` 177 (STATUS), `monitor.go RenderSingleInterface` 178 (NEW-low), `ddns manager policyFromConfig` 167 (NEW). No uncataloged god-function was missed.


## 6. Findings

Each block below retains the exact field labels (Title / Severity / Confidence / Refactor class / Dedup tag / Evidence / Proposed decomposition / Hot-path preservation analysis / Tests + gate / Why it matters / Fix direction / Labels / Dedup note) as written by the module-audit agent, prefixed with its group tag.

### 6.1 High confidence (57)

#### [A1-rust-hotpath] F1 — `poll_binding_process_descriptor` is ~4,724 LOC, not 1,368 — the god-function grew 3.4× while only helpers were peeled

- **Title:** `poll_descriptor/mod.rs::poll_binding_process_descriptor` RX god-loop is ~4,724 LOC (single fn); #4404's tracked size (1,368) is stale and the "one increment landed" only removed a 99-LOC debug helper.
- **Severity:** HIGH (top REFACTOR-tier item in the repo; reviewability + inlining-unit risk).
- **Confidence:** HIGH (line-exact: fn body 603→5326; `grep '\bfn '` between confirms zero nested/sibling fns in that span; inline tests start 5328).
- **Refactor class:** (B) REQUIRES GUARDRAILS — the cold sub-blocks are perf-positive to peel (C), but the *whole* extraction touches the hot session-hit branch wiring, so it is gated.
- **Dedup tag:** INCREMENT(#4404) / STATUS-UPDATE.
- **Evidence** (the entire body is one `while let` loop; phase map by line):
  ```
  603  pub(super) fn poll_binding_process_descriptor( … 15 params … ) {
  620      let mut received = binding.xsk.rx.receive(available);
  624      while let Some(desc) = received.read() {          // ~4,700 LOC single loop
  631          let disposition = classify_metadata(meta, validation);
  647          … stage_link_layer_classify / stage_native_gre_decap
  668          … stage_parse_flow_and_learn / stage_classify_fabric_ingress
  690          match stage_screen_check( …
  727          match stage_ipsec_passthrough_check( …
  771          match stage_flow_cache_hit( …               // SESSION-HIT fast path branch
  1275         } else { session_misses += 1;               // SESSION-MISS branch
  1278            stage_screen_syn_cookie_ack_on_session_miss( …
  1396            // --- DNAT pre-routing ---
  1491            // --- NPTv6 inbound pre-routing ---
  1509            // --- NAT64 pre-routing ---              // ~487 LOC inline block
  1996            … strict-syn-check / forwarding resolution / policy / host-inbound / fabric / HA
  3768         if matches!(…ForwardCandidate|FabricRedirect) { … forward-commit … }
  4219         else { match decision.resolution.disposition {  // terminal dispatch ~1,490 LOC
  4220            LocalDelivery => …  NoRoute => …  MissingNeighbor => …  PolicyDenied => …
  5256         … telemetry.dbg.* counters
  5322      received.release(); drop(received);
  5326  }
  ```
  Approximate phase sizes: parse/classify ~59; screen+ipsec ~81; **session-hit branch ~503**; **session-miss+DNAT/NPTv6/NAT64 ~722** (NAT64 alone ~487); **forward-resolve+policy+host-inbound+fabric+HA ~1,772**; **terminal-disposition dispatch ~1,488**; telemetry ~71.
- **Proposed decomposition** (refines #4404's `stages/{…}` proposal with line seams; the shared-context seam ALREADY EXISTS — `WorkerContext<'a>`/`TelemetryContext<'a>` in `types/runtime.rs:417/457` are threaded as params 617/618):
  - Keep the `while let` driver + parse/classify/screen/ipsec (603–770) and the **session-hit branch (771–1274)** in `mod.rs` — this is the hot inline core; `stage_flow_cache_hit` is already its own D-class module.
  - `poll_descriptor/nat_prerouting.rs` ← DNAT/NPTv6/**NAT64** pre-routing (1396–1995, ~600 LOC). Session-miss only → `#[cold] #[inline(never)]` (same discipline as `nat_exception.rs`). Highest-value single extraction; the 487-LOC NAT64 block is pure cold pre-routing.
  - `poll_descriptor/forward_resolve.rs` ← forwarding resolution + policy eval + host-inbound + fabric + HA (1996–3767, ~1,772 LOC). Largest block; session-miss/slow path.
  - `poll_descriptor/disposition_dispatch.rs` ← forward-commit + terminal `match disposition` arms (3768–5255, ~1,488 LOC). Terminal/slow.
  - `poll_descriptor/telemetry_debug.rs` ← the counter tail (5256–5326).
  - Each stage takes `(&mut binding, &mut sessions, &mut screen, worker_ctx, telemetry, desc, meta, &flow, now_ns, now_secs)` and returns a `StageOutcome` (the enum already used by `stage_screen_check` etc.).
- **Hot-path preservation analysis:**
  - The established-flow fast path is the `stage_flow_cache_hit` branch (771–1274); everything proposed for extraction is on the **session-MISS / terminal** side, which an established flow never reaches. So extracting NAT64/forward-resolve/disposition as `#[cold] #[inline(never)]` is **performance-POSITIVE** — it shrinks the hot ingress loop's codegen unit and pulls ~3,800 LOC of cold `.text` out of the icache window the fast path competes for.
  - **Recycle-once invariant (#2208) is the sharp edge.** Every early-exit inside the loop must recycle the ingress descriptor exactly once via the loop finalizer. Extracted stages MUST NOT `continue`/`return` past the finalizer — they must return a `StageOutcome` (RecycleAndContinue / …) the driver honors, mirroring the existing screen/ipsec stages. A bare `continue` moved into a helper leaks the UMEM frame (worker stall under TX congestion). This is the verification-critical seam.
  - No new heap alloc, no dyn dispatch, no fn-pointer registry (the CLAUDE hot-path rule + catalog §2 forbid a "dynamic stage registry"): keep the flat monomorphized `match`; stages are same-crate `#[inline]`-eligible free fns, not trait objects.
  - Carry the `let raw_frame` bind reuse (line-50 raw_frame, referenced by the Time-Exceeded builder at ~1254 and the LocalDelivery reinject) — a stage boundary must re-borrow, not re-slice, or the `desc.addr`-referencing TxRequests break.
- **Tests + gate:** the `txn_*` differential tests in `tests.rs` (`txn_run_descriptor`, `_with_deliveries`, `_capturing_events`, `txn_flow_cache_entries` ~7498–7900) drive the WHOLE `poll_binding_process_descriptor` and assert deliveries/events/flow-cache state — they are the behavioral gate and must keep passing byte-for-byte across the split. Plus `make test` (Go+Rust) and a `make test-failover` run (HA/session-miss paths move). Recommend a `cargo asm` diff on the `stage_flow_cache_hit` fast path to prove the hot branch codegen is unchanged.
- **Why it matters:** a 4,700-LOC function is a single inlining/optimization unit the compiler must re-analyze on every edit to any of 15 subsystems; it is unreviewable (the #4404 rationale) and every new feature (NAT64, flowless #3291, fabric #4155, host-inbound #3609, strict-syn #4400) has been *inlined into it*, so it grows monotonically. The cold bulk actively competes for icache with the fast path.
- **Fix direction:** land `nat_prerouting.rs` first (cleanest cold seam, self-contained, biggest single win), then `disposition_dispatch.rs`, then `forward_resolve.rs`; keep the driver + session-hit branch in `mod.rs`. One extraction per PR, each gated on the `txn_*` differential suite + a fast-path `cargo asm` diff.
- **Labels:** refactor, hot-path, rust-dataplane, monolith, #4404.
- **Dedup note:** #4404 is OPEN and cited "1,368 LOC / inc-1 landed". This corrects the size to ~4,724, supplies exact phase seams and the existing `WorkerContext`/`TelemetryContext` seam (catalog said "via shared PacketCtx/DescriptorContext" — those don't exist under those names; the equivalents already exist), and adds the #2208 recycle-once StageOutcome constraint the catalog omits.

#### [A1-rust-hotpath] F4 — `afxdp/tests.rs` (13,598 LOC, 199 flat tests): concrete cluster→module split plan

- **Title:** `afxdp/tests.rs` is 199 tests in one flat file; map clusters to per-production-module `tests.rs` siblings and keep the `txn_*` differential pipeline tests as the hot-path gate.
- **Severity:** LOW (review-cost; excluded from the audit heatmap).
- **Confidence:** HIGH (199 `#[test]`; no sub-`mod` structure; clusters derived from name-prefix histogram).
- **Refactor class:** (A) MECHANICAL.
- **Dedup tag:** INCREMENT(codex-171-29).
- **Evidence:** name-prefix histogram → subjects: `poll_descriptor`(17), `policy_inbound`(12), `gre_decap`/`native_gre`/`gre_to`(~21), `time_exceeded`/`icmpv6_te`/`icmp_err`/`icmp_suppress`/`reject_icmp`/`embedded_icmp`(~30), `flowless_non`/`frag_test`/`non_first`(~12), `static_nat`/`dnat_v6`/`publish_dnat`/`inbound_dnat`/`record_nat64`(~15), `fabric_queue`/`synced_replica`/`shared_umem`(~10), `output_filter`(3), `worker_binding`(3), `maybe_reinject`/`slow_path`/`handle_forward`(~10), `txn_*` differential(~15).
- **Proposed decomposition** (colocate next to the production seam each cluster exercises — #1034/#1046 pattern):
  | Cluster | Target |
  |---|---|
  | `txn_*` differential (full `poll_binding_process_descriptor` golden traces), `poll_descriptor_*`, `disposition_counters_*` | `poll_descriptor/tests.rs` — **the hot-path behavioral gate; must keep gating (see F1)** |
  | `gre_decap`/`native_gre`/`gre_to`/`tunnel_*` | `poll_stages`/`forwarding` GRE tests (next to decap/encap) |
  | `time_exceeded`/`icmpv6_te`/`icmp_err`/`icmp_suppress`/`reject_icmp`/`embedded_icmp` | `icmp`/`icmp_ptb`/`reject_reply` tests |
  | `static_nat`/`dnat_*`/`publish_dnat`/`record_nat64` | `checksum`/`nat64` tests |
  | `flowless_non`/`frag_test`/`non_first` | `poll_stages`/`poll_descriptor` flowless tests |
  | `fabric_queue`/`synced_replica`/`shared_umem` | `worker`/`shared_ops` tests |
  | `output_filter`/`policy_inbound` | `poll_descriptor/filter` tests |
  | `maybe_reinject`/`slow_path`/`handle_forward` | `tx/dispatch`/`slowpath` tests |
- **Hot-path preservation analysis:** none (tests). The one contract: the `txn_*` differential tests exercise the entire RX loop end-to-end — they MUST move as a unit (with their `txn_run_descriptor*` helpers) and remain the gate for F1's extraction. Do not scatter them across the per-feature files.
- **Tests + gate:** `make test-rust` after each cluster move (behavior-preserving by construction).
- **Why it matters:** a 13.6K-LOC flat test file is the review-cost twin of the F1 production monolith; splitting it per-seam lets F1/F2/F3 land their tests next to the code and shrinks the diff blast radius.
- **Fix direction:** move clusters in the same PRs that split their production counterparts (tests follow code), starting with the `txn_*`+`poll_descriptor` cluster alongside F1's first extraction.
- **Labels:** test-split, rust-dataplane, codex-171-29.
- **Dedup note:** codex-171-29 lists `afxdp/tests.rs 13,598` as open with no plan; this supplies the cluster→module map and flags `txn_*` as the load-bearing differential gate.

#### [A1-rust-hotpath] F6 — Systemic: the REFACTOR/WATCH heatmap over-reports this subtree because the audit script counts inline `mod tests`

- **Title:** across `poll_descriptor/` + `poll_stages.rs`, the committed heatmap tiers are dominated by inline test blocks the audit script deliberately does not strip; correcting for it changes which files are real monoliths.
- **Severity:** LOW (audit-methodology note, not a code defect) — but it reframes F2/F5 and any future pass over this subtree.
- **Confidence:** HIGH (measured per file).
- **Refactor class:** (A) MECHANICAL (the remedy is test colocation, which the project already does elsewhere).
- **Dedup tag:** NEW (angle: `docs/refactoring-audit.md` acknowledges the over-count "acceptable at 1500-2000"; here it pushes files past the 2000 REFACTOR line).
- **Evidence:** prod-vs-total for this group — `reject_reply` 414/2174 (81% test), `poll_stages` 972/3527 (72%), `cookie_reply` 127/509 (75%), `mod.rs` 5327/6042 (12% — the genuine monolith), `filter` 639/1201 (47%). Two files cross the 2,000 REFACTOR threshold **only** because of inline tests.
- **Proposed decomposition:** adopt the #1034/#1046 sibling-`tests.rs` pattern uniformly for `poll_descriptor/*` and `poll_stages.rs` (F2, F5, F4). After that, the only file in this group over 2,000 prod LOC is `poll_descriptor/mod.rs` (F1) — the true target.
- **Hot-path preservation analysis:** none (test relocation).
- **Tests + gate:** `make test-rust`; and consider whether `scripts/refactoring-audit.sh` should optionally report a prod-only column so the heatmap ranks by production LOC (out of scope here — inspection-only).
- **Why it matters:** the dedup summary itself warns the heatmap is "directional, re-run the script"; this quantifies that for the hottest subtree so effort lands on `mod.rs`, not on churning cohesive test-heavy files.
- **Fix direction:** batch the test relocations (F2/F4/F5) so the heatmap re-ranks to reflect production reality; then #4404/F1 is unambiguously the sole REFACTOR-tier production file here.
- **Labels:** audit-methodology, test-colocation, rust-dataplane.
- **Dedup note:** complements codex-171-29 (which lists sibling `_tests.rs` files) by covering the INLINE `mod tests` blocks that still inflate production-file tiers.

---

#### [A2-rust-fwd-frame] F2 — Dead `IcmpTeRateLimiter` in `forwarding/mod.rs` (uncataloged dead code)

**Title:** `forwarding/mod.rs:1240-1274` carries a fully dead
`IcmpTeRateLimiter` struct + `ICMP_TE_MAX_PER_SEC` const, superseded by the
GCRA token bucket in `icmp_ratelimit.rs`.
**Severity:** Low · **Confidence:** High
**Refactor class:** (A) mechanical · **Dedup tag:** NEW (not in dedup §1d dead-code list)

**Evidence** (`forwarding/mod.rs:1240-1274`):
```rust
#[allow(dead_code)]
const ICMP_TE_MAX_PER_SEC: u32 = 100;
/// Rate limiter for ICMP Time Exceeded messages.
#[allow(dead_code)]
struct IcmpTeRateLimiter { max_per_sec: u32, count: u32, window_start_ns: u64 }
#[allow(dead_code)]
impl IcmpTeRateLimiter { fn new(..){..} fn allow(&mut self, now_ns: u64)->bool {..} }
```
All three carry `#[allow(dead_code)]`; no production caller. ICMP Time-Exceeded
rate limiting is now the shared per-reason GCRA bucket
(`icmp_ratelimit.rs`, wired at the three generation sites per
`afxdp/README.md`). This is a stale pre-GCRA window-counter left behind.

**Proposed decomposition:** delete the const + struct + impl (35 LOC). No move.

**Hot-path preservation analysis:** none — dead code, no callers, no layout.

**Tests + gate:** none needed; `make test-rust` confirms nothing referenced it.

**Why it matters:** dead `#[allow(dead_code)]` in a REFACTOR-tier hot file
misleads the reader that a second, divergent TE rate limiter exists (there is a
real one). Deleting it shrinks the facade-split surface.

**Fix direction:** delete lines 1240-1274. **Labels:** dead-code, cleanup.
**Dedup note:** ADD to dedup §1d.

---

#### [A2-rust-fwd-frame] F3 — `forwarding/mod.rs` facade split: seam validated + fn→file map + preservation pins

**Title:** Validate & refine the cataloged
`{fabric,ha,neighbors,mss,tunnel,classification,icmp,route,local}` facade for
the 2820-LOC `forwarding/mod.rs`.
**Severity:** Medium (reviewability) · **Confidence:** High
**Refactor class:** (B) requires guardrails · **Dedup tag:** INCREMENT (dedup §1b, agy-171-04 / codex-171-4)

**Evidence:** the file is a genuine REFACTOR-tier monolith (>2000 prod LOC)
mixing ≥9 responsibilities. Concrete current fn boundaries (validated against
HEAD) map to the proposed facade as:

| Proposed submodule | Functions (line) |
|---|---|
| `classification.rs` | `classify_metadata`(29), `parse_packet_destination`(237), `is_icmp_echo_request`(818), `is_ipsec_traffic`(1302), `classify_ipsec_admission`(1345), `IpsecAdmissionClass`(1312) |
| `neighbors.rs` | `classify_neighbor_state`(203)+`NeighborStateClass`(197), `neighbor_state_usable`(233), `lookup_neighbor_entry`(2550, **HOT**), `parse_neighbor_entries`(2572), `NEIGHBOR_UNKNOWN_STATE_SKIPPED` static |
| `fabric.rs` | `record_fabric_skip`(113), `build_fabric_link_or_skip`(136), `resolve_fabric_links_from_snapshots`(553), `resolve_fabric_redirect*`(586/592/624/635), `redirect_via_fabric_if_needed`(655), `ingress_is_fabric*`(537/543), `prefer_local_forward_candidate_for_fabric_ingress`(669), `cluster_peer_return_fast_path`(713), `FABRIC_LINK_*` statics |
| `ha.rs` | `owner_rg_for_flow`(502), `owner_rg_for_resolution`(510), `enforce_ha_resolution*`(845/858/868), `cached_flow_decision_valid`(918), `finalize_new_flow_ha_resolution`(978), `demoted/activated_owner_rgs`(1007/1023) |
| `nat_scope.rs` | `nat_scope_ctx_for_flow`(298), `match_source_nat_for_flow*`(326/350/373) |
| `zone.rs` | `zone_pair_for_flow*`(420/428), `zone_pair_ids_for_flow_with_override`(463, **HOT `#[inline]`**), `allow_unsolicited_dns_reply`(493), `resolve_ingress_logical_ifindex`(834) |
| `mss.rs` | `effective_tcp_mss`(1050), `native_gre_inner_mtu`(1054), `native_gre_tcp_mss`(1089), `tunnel_outer_mtu`(1125), `tunnel_tcp_mss`(1173), `select_tcp_mss`(1220) |
| `route.rs` | `canonical_route_table`(48), all `lookup_forwarding_resolution*`(1385-1603, **HOT**), `_v4/_v6[_inner]`(1997/2023/2215/2239, **HOT inner loops**), `resolve_tunnel_*`(2448/2486), `outer_neighbor_ifindex`(2536), `choose_v4/v6_route`(2622/2642), `ecmp_hash_*`(2685-2729), `tunnel_next_hop_live`(2786), `select_route_next_hop`(2799), `no_route_resolution`(2423), `ResolvedRouteV4/V6` |
| `pbr.rs` | `PbrRejectSink`(1611), `RouteOverride`(1624), `ingress_route_table_override`(1641) — matches the cataloged "move PBR to filter/pbr.rs" |
| `local.rs` | `interface_nat_local_resolution*`(1763/1809), `should_cache_local_delivery_session_on_miss`(1817), `install_helper_local_session_on_miss`(1872), `should_block_tunnel_interface_nat_session_miss`(1934), `ingress_interface_local_resolution*`(1946/1987) |

The catalog's 9-way list omits **`nat_scope`, `zone`, `pbr`, `local`** as
distinct seams — add them; `local.rs` alone is ~250 LOC of session-miss
local-delivery logic the facade list buries under "route".

**Hot-path preservation analysis (mandatory pins):**
- `lookup_forwarding_resolution_v4_inner` / `_v6_inner` are the FIB hot loops
  (linear scan of `routes_vX.get(table)` + `connected_vX.iter()`); they call
  `lookup_neighbor_entry`, `choose_vX_route`, `select_route_next_hop`,
  `ecmp_hash_*`, `tunnel_next_hop_live`, `resolve_tunnel_*` **recursively**.
  Moving `route.rs` MUST keep this whole cluster in ONE file, else the mutual
  recursion crosses a module boundary — same-crate so inlining is preserved by
  the compiler, but split them across files only together, not scattered.
- `zone_pair_ids_for_flow_with_override` (463) is `#[inline]` and read on every
  session-miss/host-inbound zone derivation — keep the attribute when moved.
- `lookup_neighbor_entry` (2550) is called from inside the FIB loops — if it
  goes to `neighbors.rs` it MUST stay a cross-module `#[inline]` (verify with
  `cargo asm` that the FIB inner still inlines the neighbor probe).
- `ForwardingResolution` is a register-passed POD (dedup §1f, agy-171-26) — the
  `no_route_resolution`/struct-literal returns must not become a heap type.
- No new `dyn`/`Box`; `select_route_next_hop`'s stack `SmallVec<[&T;8]>`
  (2809) stays.

**Tests + gate:** the facade is a pure `pub(super) use route::*;` re-export, so
all call sites resolve unchanged. `forwarding/tests.rs` (4632) should be split
into per-submodule `tests.rs` in the SAME PR (it already groups by concern).
Gate: `make test-rust` + `make test-failover` (fabric/HA arms move) + a
new-flow throughput iperf3 smoke (≥23 Gbit/s, no regression) since the FIB loop
moved.

**Why it matters:** at 2820 prod LOC this is the #1 non-test WATCH/REFACTOR file
in the group; the facade is achievable as pure re-exports with no behavior
change, and the fn boundaries above are already clean.

**Fix direction:** facade `mod.rs` + 10 submodules per the table.
**Labels:** modularity, refactor, hot-path. **Dedup note:** extends agy-171-04
with the missing `nat_scope/zone/pbr/local` seams + explicit hot-loop
co-location pin.

---

#### [A2-rust-fwd-frame] F4 — `forwarding_build/mod.rs` god-function `build_..._and_previous` (~410 LOC, cold)

**Title:** The snapshot→`ForwardingState` builder
`build_forwarding_state_with_policy_counters_and_previous` is a ~410-LOC
god-function assembling the 64-field god-struct in one body.
**Severity:** Medium · **Confidence:** High
**Refactor class:** (A) mechanical (cold config-apply, no hot path)
**Dedup tag:** NEW (uncataloged — forwarding_build was not in the dedup catalog)

**Evidence** (`forwarding_build/mod.rs:200-~613`): one function spans lines
200→613. The per-domain populate helpers already exist in siblings
(`fib.rs::populate_fabrics/neighbors`, `interfaces.rs::populate_interfaces`,
`zones.rs::populate_zones`, `tunnels.rs`, `cos.rs`), so the parent is a long
sequential driver that (a) parses `syn_cookie_master_key`, (b) computes
`pending_neigh_timeout_ns` (via `compute_pending_neigh_timeout_ns`, 641), (c)
calls each populate_*, (d) folds in the late-stage NAT local-table append
(`local_tables_v*`/`local_nat_any_table_v*`, referenced by types/forwarding.rs
comments), (e) merges the `previous` state for identity-preserving reuse (WG
engines, fabric preserve-merge).

**Proposed decomposition:** extract 3-4 cold phases —
`resolve_neigh_timeout(snapshot) -> u64`, `append_nat_local_tables(&mut state,
..)`, `merge_preserved_previous(&mut state, previous)` — leaving the parent a
readable sequence of `populate_* / phase_*` calls. Pure cold-path extraction.

**Hot-path preservation analysis:** none — runs on config-apply /
`bump_fib` only, never per packet. No inlining, layout, or alloc concern.

**Tests + gate:** `forwarding_build/tests.rs` (5042) already exercises the
build; the extraction is refactor-neutral. Gate: `make test-rust`.

**Why it matters:** the single largest cold god-function in the group; it's the
one place the 64-field struct is populated, so its length compounds the
god-struct problem (F7) — splitting it makes both reviewable.

**Fix direction:** phase-extract into `forwarding_build/{assemble,merge}.rs`.
**Labels:** modularity, cold-path. **Dedup note:** ADD forwarding_build to the
catalog (currently absent).

---

#### [A2-rust-fwd-frame] F5 — `neighbor.rs` low cohesion + `neigh_monitor_thread` god-fn + misplaced CPU/MAC utils

**Title:** `neighbor.rs` fuses six unrelated subsystems; the netlink monitor
`neigh_monitor_thread` is a ~271-LOC god-function, and CPU-pinning + MAC-format
helpers don't belong in a neighbor module.
**Severity:** Medium · **Confidence:** High
**Refactor class:** (A/B) mostly mechanical (all cold: monitor thread, warmer,
config-time)
**Dedup tag:** INCREMENT (dedup §1b agy-171-19 / codex-171-19 "probe/netlink/warmer/cpu/decision/handle/loop.rs")

**Evidence:** `neighbor.rs` (2036 raw; ~940 prod across **four** inline
`#[cfg(test)]` blocks at 480/1341/1710/1879) contains, in one file:
- `monotonic_nanos`/`monotonic_timestamp_to_datetime` (3-37) — a clock util
- probe-socket selection + ICMP echo build (38-127) — socket setup
- `trigger_kernel_arp_probe` (158, ~133 LOC) — worker-facing probe
- `neighbor_warmer_loop` (292, ~119 LOC) — a background thread
- `build_newneigh_request`/`add_kernel_neighbor`/`update/remove_dynamic_neighbor`
  (412-587) — kernel-neigh write
- `parse_neighbor_msg`/`request_neighbor_dump`/`process_dump_batch`/
  `initial_neighbor_dump`/`dump_establishes_baseline` (599-909) — dump parsing
- `neigh_monitor_thread` (975-1246, **~271 LOC**) — the netlink monitor loop
- `nth_allowed_cpu`/`pin_current_thread` (1247-1321) — **CPU pinning** (unrelated)
- `parse_mac`/`format_mac` (1322-1340) — **MAC string utils** (unrelated)

`neigh_monitor_thread` (975-1246) has clean internal phases (socket
create/subscribe/bind, rcvbuf enlarge, recv-timeout, the #2919 initial-dump
retry `loop`, steady-state recv loop with ENOBUFS re-dump throttle) — verified
via its own phase comments — but they're inlined into one function.

**Proposed decomposition** (matches the cataloged split, now with boundaries):
- `neighbor/monitor.rs` — `neigh_monitor_thread` split into
  `open_monitor_socket()`, `acquire_initial_baseline(stop)` (the #2919 retry
  loop), `monitor_recv_loop(...)` (steady-state + ENOBUFS re-dump); plus the
  dump parsers (`process_dump_batch`, `parse_neighbor_msg`, `initial_dump`).
- `neighbor/warmer.rs` — `neighbor_warmer_loop`.
- `neighbor/probe.rs` — probe-socket select + ICMP echo + `trigger_kernel_arp_probe`.
- `neighbor/kernel.rs` — `build_newneigh_request` + `add_kernel_neighbor` + dyn-neigh mutate.
- **`worker/cpu.rs`** (NOT under neighbor) — `nth_allowed_cpu` + `pin_current_thread`.
  Cross-check: `afxdp/README.md` explicitly documents `pin_current_thread` as
  living "in `neighbor.rs`" — a cohesion smell the doc itself records.
- **`neighbor/mac.rs` or a crate `mac` util** — `parse_mac`/`format_mac`
  (also used by `forwarding/mod.rs` fabric resolution).
- Colocate the four inline test blocks into `neighbor/tests.rs` (this alone
  removes the raw-LOC REFACTOR flag).

**Hot-path preservation analysis:** everything here is off the per-packet
forwarded path (monitor + warmer are their own threads; `trigger_kernel_arp_probe`
is cold-path; `pin_current_thread` runs once at worker start). `parse_mac` is
called on config-build and fabric-refresh, not per packet. No inlining/layout
pins — Class A. Keep `monotonic_nanos` inline-able (used widely) — it can move
to a `time` util but must stay `#[inline]`.

**Tests + gate:** the four inline test blocks pin the dump-batch/CPU-mask/socket
behavior; move them next to the code. Gate: `make test-rust`; the neighbor
monitor is exercised by `make test-failover` (neighbor re-resolution on
failover) — run it since monitor code moves.

**Why it matters:** the `[REFACTOR]` flag here is HALF test-inflation and HALF
genuine low cohesion; separating the two lets the real 940 prod LOC split by
subsystem, and pulls `cpu`/`mac` utils out of a security-sensitive neighbor
file where they're invisible.

**Fix direction:** `neighbor/{monitor,warmer,probe,kernel,mac}.rs` +
`worker/cpu.rs`. **Labels:** modularity, cohesion, cold-path.
**Dedup note:** INCREMENT agy-171-19 with the `neigh_monitor_thread` god-fn
boundary + the cpu/mac mis-placement (both new detail).

---

#### [A2-rust-fwd-frame] F6 — `neighbor_dispatch.rs` (FRESH) `retry_pending_neigh` ~255-LOC god-fn; file is test-inflated

**Title:** The pending-neighbor retry sweep `retry_pending_neigh` is a ~255-LOC
god-function; the file's 1399 raw LOC is ~60% inline tests (prod ~599).
**Severity:** Low-Medium · **Confidence:** High
**Refactor class:** (A) mechanical (cold sweep, explicitly off the per-packet
fast path per its own doc comment)
**Dedup tag:** NEW (neighbor_dispatch.rs uncataloged — "fresh" per brief)

**Evidence** (`neighbor_dispatch.rs:156-411`): `retry_pending_neigh` has 12
parameters (already over the >8 refactor cue) and three clear phases inside one
per-key loop:
```rust
for key in keys {                          // snapshot of distinct unresolved hops
    // (1) timeout arm: neg-cache + recycle frame + drop  (213-233)
    // (2) still-pending arm: re-fire probe if probe_due   (242-258)
    // (3) resolved arm: record dwell, own the pkt, dispatch tail (260-411, ~150 LOC)
}
```
The comment at 165-170 confirms it fires "only on the rare retry-sweep events
... all off the per-packet forwarded fast path". Production code ends ~599;
tests (600-1399) are ~800 LOC — the file is NOT a monolith by production LOC.

**Proposed decomposition:**
- Extract the phase-3 resolved-dispatch tail into
  `dispatch_resolved_pending(binding, left, right, .., key, pkt, neighbor_mac)`
  (~150 LOC — the CoS/slice/target/mirror logic).
- Extract phase-1 timeout into
  `drop_timed_out_pending(binding, key, now_ns, resolver)`.
- Group the 12 params into a `PendingRetryCtx<'_>` context struct (the
  neighbor-list borrows + forwarding + resolver + area).
- Split the inline tests into `neighbor_dispatch/tests.rs`.

**Hot-path preservation analysis:** cold sweep — no inlining/alloc/layout
pins. The `keys: Vec<(i32,IpAddr)>` snapshot (204) already allocates per sweep
but is bounded by distinct unresolved hops (tiny) and off the fast path;
extraction doesn't add allocs. Preserve the `&mut binding` + `left`/`right`
slice-split borrow discipline (the reason phase-3 owns the pkt out of the map
first, 272-275) — the extracted fn must take the same split-borrow shape.

**Tests + gate:** the ~800 LOC of inline tests already pin timeout/probe/dwell
behavior; move them beside the code. Gate: `make test-rust` + `make test-failover`
(pending-neigh drives first-packet forwarding after failover).

**Why it matters:** a 12-param 255-LOC function with a nested 3-arm loop is the
group's clearest uncataloged god-function; the borrow-split makes it hard to
read, and the fix is a mechanical context-struct + tail extraction.

**Fix direction:** `PendingRetryCtx` + `dispatch_resolved_pending`.
**Labels:** modularity, god-function, cold-path. **Dedup note:** ADD
neighbor_dispatch.rs to the catalog.

---

#### [A3-rust-cos-tx] F1 — INCREMENT(#4408): `enqueue_pending_forwards` next increment = Phase-8 build body

- **Title**: TX-drain god-fn `enqueue_pending_forwards` — extract the size-changing forward-build block (Phase 8)
- **Severity**: Medium (reviewability; the hottest single function in TX)
- **Confidence**: High
- **Refactor class**: **(B) REQUIRES GUARDRAILS**
- **Dedup tag**: INCREMENT(#4408) — inc1 (`compute_forwarded_egress_ptb`) landed; this names inc2 precisely.
- **Evidence**: `tx/dispatch/mod.rs:270–1318`. The fn is now ~1,048 LOC (brief cited 1,131 — trimmed by inc1). Single `for request in pending_forwards.iter_mut()` loop with distinct phases:
  ```
  326–405   Prebuilt fast-path (enqueue + fabric-unsendable count + recycle)
  407–440   source-frame read (Live/Owned) + sampled mirror clone
  443–505   target-binding resolve + no-binding fail-closed
  520–653   TCP segmentation (prepared + from_frame builders)
  654–1200  !copied_source_frame → PTB decision + in-place rewrite (709–881)
            + direct-TX build (882–1059) + Vec-copy fallback (1061–1198)   <-- ~545 LOC
  1202–1224 batch drain + shared recycles
  1225–1283 PTB finalizer (classify_generated_reply + enqueue)
  1284–1307 build_failed handling + single-recycle finalizer
  ```
  The `if !copied_source_frame { ... }` block (654–1200, ~545 LOC) is the mass. It contains THREE near-identical build sub-paths (in-place / direct-TX / Vec-copy) each repeating the oversized-check + enqueue + `dbg.enqueue_*`/`tx_bytes_total`/`tx_max_frame` counter block.
- **Proposed decomposition**: extract the size-changing build block into `tx/dispatch/build_forward.rs::build_and_enqueue_forward(...) -> ForwardBuildOutcome` returning a flat enum `{ Enqueued, RetainedInPlace, BuildFailed{reinject:bool}, MtuSignalled }`. State it needs: `target_binding: &mut BindingWorker`, `ingress_area`, `request` fields, `source_frame`, `expected_ports`, `forwarding`, `post_recycles`, `dbg`, `counters`, `worker_id`, `worker_commands_by_id`. The three build sub-paths collapse to one helper each (`try_inplace`, `try_direct_tx`, `copy_fallback`) with a shared `record_forward_enqueue(dbg, target_binding, len)` for the repeated counter block. The `DirectTxFallbackReason` enum (883–887) moves with it.
- **Hot-path preservation analysis**: The three build helpers MUST carry `#[inline]` across the new module boundary (crate has `codegen-units 16`, LTO off — the same reason `try_bump_outstanding` in lease.rs documents `#[inline]`, `#2158 §6`). Preserve: (1) **UMEM single-recycle** — `retained_source_frame` is set true ONLY on the in-place branch (750); every other exit falls through to the `if !retained_source_frame { recycle_ingress_frame }` finalizer (1300–1307). The helper must RETURN the retain decision, never recycle itself, so the single finalizer stays authoritative (#2208). (2) no new heap alloc — `TxRequest{ bytes: frame }` moves, no clone. (3) the monomorphized flat build match (`build_forwarded_frame_from_frame` / `build_nat64_forwarded_frame` / `rewrite_forwarded_frame_in_place`) stays a concrete match, NOT `Box<dyn>`. (4) `copy_frame_is_oversized` / `direct_tx_tuple_mismatch_reason` `#[cfg(test)]` fault-injection wrappers (75–112) DCE in release — keep the bare comparison in the hot arm.
- **Tests + gate**: `dispatch_tests.rs` (1,564) — the `FORCE_OVERSIZED` and `FORCE_TUPLE_MISMATCH` fault-injection tests (guard the single-recycle-on-oversized and no-double-recycle-on-mismatch invariants) move/re-point to the new helper. Gate: `make test-rust` + `cargo asm` diff on `enqueue_pending_forwards` (confirm inlining preserved, no new `memcpy`/alloc) + `make cluster-deploy` iperf3 -P16 ≥23 Gbit/s no-regression.
- **Why it matters**: 1,048-LOC fn is the top single-function reviewability defect in the TX path; the triplicated build+counter blocks are a drift hazard (a counter fix must be applied 3×).
- **Fix direction**: land inc2 = Phase-8 body extraction only; keep the loop skeleton + finalizer in `mod.rs` so the recycle invariant stays visible in one place. Defer Phase-4 (segmentation) and Phase-1 (prebuilt) extractions to inc3/inc4.
- **Labels**: refactor, hot-path, tx-drain, #4408
- **Dedup note**: #4408 is OPEN; inc1 landed. This is the concrete inc2 boundary the catalog’s generic "phase_build/phase_segment/phase_mirror" note lacked.

#### [A3-rust-cos-tx] F2 — INCREMENT(#4408) + STATUS-UPDATE: `queue_service/mod.rs` crossed 2,000; waterfill + cfg(test) dead-weight

- **Title**: CoS `queue_service/mod.rs` is now REFACTOR-tier (2,058); waterfill god-fn + test-only selectors inflate it
- **Severity**: Medium
- **Confidence**: High
- **Refactor class**: mixed — **(A)** for the `#[cfg(test)]` selector move; **(B)** for the waterfill epoch-refill + settle peel
- **Dedup tag**: INCREMENT(#4408) + STATUS-UPDATE
- **Evidence**:
  - **STATUS-UPDATE**: file is **2,058 LOC** at HEAD; committed heatmap says `[WATCH] 1,880`. It has crossed the 2,000 `[REFACTOR]` threshold — the heatmap is stale (regenerate `scripts/refactoring-audit.sh`). Per the engineering-style rule "by ~3,000 the next change splits first" and "a change that adds >100 LOC to a REFACTOR-tier file splits before landing", this file is now gated.
  - The waterfill selector `select_exact_cos_guarantee_queue_waterfill` (`mod.rs:926–1357`, ~432 LOC) is the #4408 target. Internal seams:
    ```
    958–1031  epoch-refill block (pass1 budget math, honored-bits clear)  ~74 LOC, runs ≤1×/call
    1032–1226 Phase-1 ascending honored walk (hot)
    1227–1345 Phase-2 descending residual walk (hot)
    1346–1356 Phase-2 wrap finalize
    ```
  - `#[cfg(test)]`-only legacy selectors still in the production file: `select_cos_guarantee_batch` (580–585), `select_cos_guarantee_batch_with_fast_path` (598–688, ~90 LOC), `select_exact_cos_guarantee_queue_with_fast_path` (696–708) — ~130 LOC compiled out of production but counted in the file’s LOC (and inflating the REFACTOR-tier reading). The paired `legacy_guarantee_rr` cursor field on `CoSInterfaceRuntime` is already `#[cfg(test)]` (types/cos.rs:703).
- **Cold-vs-hot split (brief’s explicit question)**: The nanosecond-budget hot core is the two selection walks (Phase-1/Phase-2, 1032–1345) — keep contiguous. Genuinely COLD (per-batch, not per-byte, at commit time): the settle/scratch block `release_exact_local_scratch_frames` / `restore_*` / `settle_exact_*_submission*` (`mod.rs:1542–1753`, ~210 LOC) — these run on the TX-commit path and do per-bucket TX accounting (`account_flow_bucket_tx`) + sojourn record. Lease accounting (`record_cos_queue_lease_acquire`, 160–180) is telemetry flush, cold. The waterfill’s inline telemetry bumps (`eligible_visits`, `phase1_admissions`, `phase2_admissions`) are interleaved into the hot walk and can’t cleanly separate without hurting borrow-locality.
- **Proposed decomposition** (three independent increments):
  1. **(A)** move the 3 `#[cfg(test)]` legacy selectors + `select_exact_cos_guarantee_queue_with_fast_path` into `queue_service/tests.rs` (already a `#[path]` sibling) or a `test_selectors.rs` — drops production file ~130 LOC, back below 2,000. Zero hot-path effect (cfg(test)).
  2. **(B)** extract the epoch-refill block (958–1031) to `waterfill_refill_pass1_budget(root, now_ns)` — self-contained, mutates only `root.waterfill_*` fields, runs ≤1×/call. Shrinks the god-fn ~74 LOC.
  3. **(B)** peel settle/scratch (1542–1753) to `queue_service/settle.rs`.
- **Hot-path preservation analysis**: (2) must stay `#[inline]` (the walk calls it once at entry; inlining lets the branch predictor fold the `time_refresh || exhausted` fast-skip). Preserve the `#[repr(align(64))]` intent — note the CoS runtime/backlog structs’ cache-line alignment lives on `SharedCoSLeaseState` (`lease.rs:74 #[repr(align(64))]`) and `PaddedAtomicU32/U64`; the selectors touch `root.waterfill_*` (single-writer owner worker, no atomics) so no false-sharing pin moves with this code. Do NOT reorder the honored-bit / `phase2_cursor` field reads (the #1743 continuity invariants are order-sensitive). (3) settle touches `free_tx_frames` recycle — preserve the `#hb166 T-7` single-recycle-on-torn-queue arms (1556–1566, 1633–1641) exactly; those are UMEM-leak guards.
- **Tests + gate**: `queue_service/tests.rs` (4,384) pins the waterfill Phase-1/2 honor/refund + settle recycle; `legacy_guarantee_rr_does_not_advance_class_cursors` pins the cfg(test) selector isolation. Gate: `make test-rust` + CoS fairness gates (`docs/fairness-regimes.md`) + `apply-cos-config.sh` + `show class-of-service interface` counter movement (flow_share/buffer) per `docs/cos-validation-notes.md`.
- **Why it matters**: file crossed the hard 2,000 gate; the ~130 LOC of cfg(test) dead-weight is a free win to get back under it; the 432-LOC waterfill is the CoS scheduler’s single largest fn.
- **Fix direction**: land increment (1) first (mechanical, un-gates the file), then (2)/(3) as guarded perf-neutral peels.
- **Labels**: refactor, hot-path, cos-scheduler, #4408, heatmap-drift
- **Dedup note**: catalog proposed generic "orchestrator/selection/waterfill/surplus/settle/submit/wakeup/dscp" split; this pins the ACTUAL current seams, the 2,000-crossing status, and the cfg(test) dead-weight the catalog didn’t name.

#### [A3-rust-cos-tx] F3 — NEW: `types/cos.rs` fuses hot runtime structs with ~350 LOC of cold config types

- **Title**: `types/cos.rs` config/classifier types are a mechanical peel out of the hot-runtime file
- **Severity**: Low (reviewability / WATCH-tier size)
- **Confidence**: High
- **Refactor class**: **(A) MECHANICAL/SAFE**
- **Dedup tag**: NEW (FlowFairState D-class is cataloged; the FILE-level config peel is not)
- **Evidence**: `types/cos.rs` is 1,786 LOC (`[WATCH] 1,580` on the stale heatmap — also drifted up). It fuses two disjoint concerns:
  - **COLD config-apply types** (built once at commit, read at classification): `CoSState` (16–31), `CoSOversubscriptionPolicy` (33–42), `CoSInterfaceConfig` (44–68), `CoSDSCPClassifierConfig` / `CoSIEEE8021ClassifierConfig` / `CoSDSCPRewriteRuleConfig` / `CoSLossPriorityRewrite` (76–124), `EqualFlowTargetPolicy` + its `parse`/`as_str` + inline `equal_flow_target_policy_tests` mod (140–247, ~107 LOC), `CoSQueueConfig` (249–296). ≈350 LOC total, all `#[derive(Clone,Debug,PartialEq)]` POD.
  - **HOT runtime types**: `FlowRrRing` (357–494, D-class perf feature), `WorkerCoS*FastPath` (502–554), `CoSInterfaceRuntime` (556–709), `CoSQueueRuntime`+`CoSQueueConfigState`+`CoSQueueHotState`+`FlowFairState`+`VMinQueueState`+`CoSQueueTelemetry` (765–1343), timer-wheel + telemetry structs.
- **D-NEGATIVE confirmation (FlowFairState, codex-173-24)**: CONFIRMED do-not-split. `FlowFairState` (922–1095) is the parallel bucket-array storage layout: `flow_bucket_bytes/head_finish/tail_finish/tx_bytes/observed_bps/last_tx_ns/pending_bytes: [u64/u32; 4096]` + `flow_bucket_items: [VecDeque; 4096]` + `FlowRrRing`. The `new_boxed` `MaybeUninit` placement constructor (1162–1208, avoids a 352 KB stack temporary, #1755) and the `const _: () = assert!(COS_FLOW_FAIR_BUCKETS.is_power_of_two())` (1701–1702) are load-bearing. Do NOT split the struct or the arrays. `CoSQueueRuntime` is ALREADY hot/cold-split into `config`/`hot`/`flow_fair_state`/`v_min`/`telemetry`/`queue_lease_v8` sub-structs — no further struct surgery needed.
- **Proposed decomposition**: move the ~350 LOC of cold config/classifier types + the `equal_flow_target_policy_tests` inline mod into a new `types/cos_config.rs`, re-exported via `pub(in crate::afxdp) use cos_config::*;` from `types/cos.rs` (mirrors the existing `types/mod.rs::use cos::*;` pattern). Drops the runtime file to ~1,430 (clear of WATCH).
- **Hot-path preservation analysis**: Zero codegen effect — type definitions do not inline; relocating a `struct` to a sibling module with unchanged `pub(in crate::afxdp)` visibility is byte-identical at the ABI. No `#[repr(align(64))]` / const-assert crosses the seam (those live with `FlowFairState`, which STAYS).
- **Tests + gate**: `cargo build` (the const-asserts must still fire) + `make test-rust`. No behavioral test needed — pure relocation. Gate: `make audit-check` after regenerating the heatmap.
- **Why it matters**: the runtime hot struct file is dominated (~20%) by config types read only at commit; separating them makes the hot-struct layout reviewable in isolation and drops the file off WATCH.
- **Fix direction**: mechanical move; opportunistic on the next CoS runtime change (per "refactor with new features").
- **Labels**: refactor, mechanical, cos-types
- **Dedup note**: catalog’s codex-173-24 is FlowFairState-struct D-class only; the file-level cold-config peel is new.

#### [A3-rust-cos-tx] F5 — NEW (uncataloged): `lease.rs` `acquire_v8_with_cause` god-fn + hot/cold status-getter fusion

- **Title**: v8 fair-share `acquire_v8_with_cause` is a ~277-LOC hot CAS god-fn fused with ~316 LOC of cold status getters
- **Severity**: Medium
- **Confidence**: High
- **Refactor class**: **(A)** for the status-getter peel; **(B/D)** for the acquire-loop split (tight atomic coupling)
- **Dedup tag**: NEW — `lease.rs` is fresh, not in the catalog (it is below the 1,500 WATCH line at 1,460, so the heatmap never surfaced it, but the god-fn is a >100-LOC finding independent of file size).
- **Evidence**: `types/shared_cos_lease/lease.rs` (1,460). One `impl SharedCoSQueueLease` block mixes:
  - **HOT god-fn** `acquire_v8_with_cause` (`lease.rs:546–823`, ~277 LOC) — per-grant on the TX admission path. Documented phases: entry request-count (573–575), Phase-1 `maybe_rotate_epoch_v8` (578), Phase-2 seqlock `snapshot_epoch_v8` (581), equal-flow cap eval (614–618), **PRIMARY PATH** tag-checked CAS loop (623–690), **SURPLUS/starvation-signal** block (692–734), **strict-fairness surplus** CAS loop (736–804), grant-side accounting (806–812), shortfall report (818–822).
  - **COLD status getters** (825–1141, ~316 LOC): ~30 one-line `self.v8.as_ref().map(...).unwrap_or(...)` accessors (`v8_bypass_grace_active`, `v8_equal_flow_*`, `v8_rollback_retry_exceeded`, `v8_worker_claim_flow`, …) read by the coordinator status overlay at ~1 s cadence. Interleaved in the same impl block as the hottest CAS loop in the CoS scheduler.
  - Seqlock reader `snapshot_epoch_v8` (1146–1189) with the #1643 `fence(Acquire)` (1179) — correctly implemented, cites cold_path_hist as reference.
- **Proposed decomposition**:
  1. **(A)** move the ~30 cold `v8_*` status getters into `types/shared_cos_lease/lease_status.rs` as a second `impl SharedCoSQueueLease { ... }` block (Rust allows split inherent impls in the same crate). Drops the file ~316 LOC → ~1,144, and physically separates the ~1 s-cadence read surface from the ns-cadence acquire loop.
  2. **(B/D — evaluate, do not auto-split)** the acquire god-fn: the PRIMARY loop (623–690) and the strict-fairness SURPLUS loop (736–804) are near-identical tag-checked-CAS structures (class CAS → try_bump_outstanding → worker_grant_bump / rollback). A shared `grant_slice(v8, &self.state, my_tag, cap, still_needed) -> u32` helper would dedup them — BUT the two loops differ in bound source (`my_effective_share` vs class-only) and the rollback-on-outstanding-cap tag threading is subtle. This is the guardrailed part; the epoch-tag/seqlock coupling argues for leaving the core loop intact and only lifting the cold getters.
- **Hot-path preservation analysis**: getter peel (1) is codegen-neutral (getters called from status, never inlined into acquire). For any acquire-loop touch: preserve every `Ordering` exactly (`Acquire` loads, `AcqRel` CAS, `Relaxed` counters — the file is explicit); preserve the tag-EQUALITY (not ordering) discipline documented at `record_equal_flow_active_sample` (u32 tag-wrap safety); preserve `try_bump_outstanding` `#[inline]` (documented `#2158 §6`, codegen-units 16 / no-LTO); the `#[repr(align(64))] SharedCoSLeaseState` (74) false-sharing pin stays with the struct.
- **Tests + gate**: `shared_cos_lease_tests.rs` (2,511) — the `test_snapshot_epoch_v8` hook (1196–1202) and the acquire/rollback/equal-flow suppression tests pin the CAS invariants. Gate: `make test-rust` + `cargo asm` on `acquire_v8_with_cause` (confirm no regression) + CoS fairness gates + `test-failover` (leases rebuild on HA failover, `matches_config_v8`).
- **Why it matters**: `acquire_v8_with_cause` is the CoS scheduler’s per-grant fast path AND a 277-LOC god-fn; sharing its impl block with 30 cold status getters buries the hot path and grows the review surface for any lease change.
- **Fix direction**: land the getter peel (mechanical, un-buries the hot path); treat the loop dedup as a separately-gated perf-neutral study, not a mechanical move.
- **Labels**: refactor, hot-path, cos-lease, v8-fairness
- **Dedup note**: entirely new — no prior campaign flagged `shared_cos_lease/lease.rs` (it post-dates the #1035-P4 split and sits under the WATCH line).

#### [A3-rust-cos-tx] F6 — NEW (uncataloged): `tx/cos_classify.rs` — two hot classification god-fns, uncataloged, nearing WATCH

- **Title**: CoS TX-classify `resolve_cos_tx_selection_internal` / `resolve_cached_cos_tx_selection` are >100-LOC per-packet god-fns
- **Severity**: Low–Medium
- **Confidence**: High
- **Refactor class**: **(B) REQUIRES GUARDRAILS**
- **Dedup tag**: NEW — `tx/cos_classify.rs` is not in the catalog’s Rust monolith list (1,335 LOC, just under WATCH 1,500).
- **Evidence**: `tx/cos_classify.rs` (1,335):
  - `resolve_cos_tx_selection_internal` (`404–694`, ~290 LOC) — the live per-packet CoS TX-selection resolve (queue-id from filter FC / DSCP BA classifier / IEEE 802.1p, loss-priority resolve, DSCP rewrite matrix).
  - `resolve_cached_cos_tx_selection` (`101–341`, ~240 LOC) — the flow-cache-hit fast path (#3778 `ba_reclassify`, cached FC-pinned vs per-packet BA-reclassify).
  - `demote_prepared_cos_queue_to_local` (1006–1130, ~124 LOC), `enqueue_local_into_cos` (759–875, ~116 LOC), `enqueue_cos_item` (1157–end).
  - 2 structs (`CoSTxSelection`, `GeneratedReplyVerdict`).
- **Cohesion**: the FILE is cohesive (all CoS TX classification). The concern is the two 240–290-LOC per-packet functions, not the file split.
- **Proposed decomposition**: within-file — split `resolve_cos_tx_selection_internal` into `resolve_queue_id` (filter-FC → DSCP → PCP → default), `resolve_loss_priority` (already partly factored at 695–758), and `resolve_dscp_rewrite` (the `(queue,lp)` matrix lookup), composed by a thin `resolve_cos_tx_selection_internal`. This keeps each classifier stage a reviewable unit. No new file needed until the file crosses WATCH.
- **Hot-path preservation analysis**: every stage helper MUST be `#[inline]` (per-packet classify; the file already relies on cross-fn inlining via `resolve_cos_queue_id`/`resolve_cos_tx_selection_at` thin shims). No heap alloc in the classify path (the `CoSTxSelection` is a POD returned by value). Preserve the #3778 `ba_reclassify` flag gating (per-packet BA re-resolve only when NOT FC-pinned) — do not collapse the cached/live paths.
- **Tests + gate**: `tx/cos_classify_tests.rs` (4,617) is the largest test file in the group — pins the classify matrix. Gate: `make test-rust` + CoS DSCP/queue counter validation (`show class-of-service interface`).
- **Why it matters**: two ~250-LOC per-packet fns in a file 165 LOC under WATCH; a single #3995-style loss-priority addition (~200 LOC) would push it over and trigger a forced split mid-feature. Refactoring the fns now (per "refactor with new features, not after") avoids that.
- **Fix direction**: within-file fn decomposition on the next CoS-classify feature; monitor file LOC against WATCH.
- **Labels**: refactor, hot-path, cos-classify
- **Dedup note**: new — no prior campaign named `tx/cos_classify.rs` (only its 4,617-LOC test file appears, as test-mass in codex-171-29).

#### [A4-rust-session-policy] F1 — policy.rs: concrete decomposition map (the map the catalog lacked)

- **Severity:** Low (modularity) · **Confidence:** High · **Refactor class:** B · **Dedup tag:** INCREMENT(#4421)
- **Evidence:** `policy.rs` 3,598 LOC, one flat file. Function/struct map (grep `^fn|^impl|^struct`):
  - Zone/book substrate: `BookEntry`(40), `zone_pair_key`(51), `zone_name_to_id_from_snapshot`(96), `PolicyAction`(124), `GlobalZoneScope`(221)+`build_global_zone_scope`(273), `PolicyRule`(291) — ~430 LOC.
  - Counters: `PolicyRuleCounter`(463, impl 500-620), `PolicyCounterStore`(622-679), `PendingPolicyHitRecord`(680)+`flush_*`(715)+`record_policy_hit_counter`(738/773 cfg-split)+`flush_recorded`(782) — ~330 LOC.
  - Applications: `PortRange`(792), `ApplicationMatch`(798), `CompiledApplications`(822)+`ProtoTerms`(830) with `from_matches`(856=96 LOC)/`matches`(953=75)/`has_l4_constrained_term`(1029), `AppCatalog`(1065)+`AppProtoEntries`/`AppScanEntry` with `from_snapshot`(1099)/`lookup_directional`(1160=81)/`lookup_forward`(1242)/`lookup_admitted`(1267) — ~450 LOC.
  - `PolicyState`(1285) + impl (counter_snapshots/hit_counter_by_idx/resolve_session_hit_counter/reresolve_session_policy_id/configured_zone_pairs) — ~370 LOC.
  - Parse: `parse_policy_state_with_counters`(1665=**558 LOC**, see F2), legacy/v3 set parsers (2223/2300/2353/2426).
  - Evaluate: thin wrappers (2447/2463/2484/2508) → `evaluate_policy_result_l3_aware`(2539=**286 LOC**, D-class), `evaluate_junos_host_policy*`(2874/2902), `rule_l3_matches`(3038), frag-deny cluster (3167-3292), `try_match_rule`(3293=47), leaf parsers (`parse_action`/`parse_address`/`parse_applications`(3436)/`parse_protocol`/`parse_port_spec`).
- **Proposed decomposition** (facade `policy/mod.rs` re-exports `pub(crate)` surface):
  - `policy/app_catalog.rs` ← AppCatalog + AppProtoEntries + AppScanEntry + CompiledApplications + ProtoTerms + ApplicationMatch + PortRange + `parse_applications` + `parse_protocol`/`parse_port_spec`/`port_ranges_match`.
  - `policy/counter.rs` ← PolicyRuleCounter + PolicyCounterStore + PendingPolicyHitRecord + `record_policy_hit_counter`/`flush_*` (the whole hit-counter batching subsystem).
  - `policy/zone.rs` ← BookEntry, zone_pair_key, GlobalZoneScope, build_global_zone_scope, resolve_policy_zone_id, zone_name_to_id_from_snapshot.
  - `policy/parse.rs` ← `parse_policy_state_with_counters` split (F2) + legacy/v3 set parsers + parse_book_prefix/resolve_book_idxs + parse_action/parse_address.
  - `policy/evaluate.rs` ← the evaluate family + frag-deny cluster + rule_l3_matches + try_match_rule. **KEEP `evaluate_policy_result_l3_aware` intact (D).**
  - `policy/state.rs` (or keep in mod.rs) ← PolicyState + PolicyRule + PolicyAction + PolicyEvaluationResult.
- **Hot-path preservation:** all evaluators are same-crate `pub(crate)`; moving to sibling modules keeps monomorphization + inlining (no trait objects introduced). `evaluate_policy_result_l3_aware` and `try_match_rule` STAY co-located in `evaluate.rs` (they call `rule_l3_matches`/`matches` tightly). AppCatalog `lookup_*` are called on the new-flow app-id path — keep them non-generic and in one module so the linear scan inlines.
- **Tests + gate:** move `policy_tests.rs` clusters alongside (F17); `make test-rust`. No dataplane behavior change → smoke `iperf3 -P16 -p5203` + `test-failover` as regression backstop (cargo-asm cannot parse this crate's symbols — see F14 note).
- **Why it matters:** 3,598 LOC is past the ~3,000 "split before adding logic" line; the app-catalog and counter subsystems are self-contained and the largest reviewability drag.
- **Fix direction:** land `app_catalog.rs` + `counter.rs` first (cleanest seams, ~780 LOC out), then parse/zone/evaluate.
- **Labels:** modularity, rust-hot-path-adjacent. **Dedup note:** supersedes the catalog's "parse/evaluate/apps" placeholder with exact fn boundaries.

#### [A4-rust-session-policy] F2 — policy.rs: `parse_policy_state_with_counters` god-fn (558 LOC)

- **Severity:** Low · **Confidence:** High · **Refactor class:** B · **Dedup tag:** INCREMENT(#4421)
- **Evidence:** lines 1665–2222 = **558 LOC**, one function. Builds the entire `PolicyState` from snapshots: zone-id map, address books, per-rule compile (address sets, application terms, counters, global scope, frag flags), rule-id assignment. Cold (compile/reconcile), not per-packet.
- **Proposed decomposition:** phase helpers in `policy/parse.rs`: `build_zone_maps`, `build_address_books`, `compile_rule(snap, &ctx) -> PolicyRule` (the per-rule body — the bulk), `assign_rule_counters`. The outer fn becomes a ~60-LOC driver looping `compile_rule`.
- **Hot-path preservation:** N/A (compile path). Only invariant: rule ORDER and rule-id assignment stay identical (positional `PolicySetID*MaxRulesPerPolicy+idx` is pinned to `show security policies` Index by #3063) — extract by pure code-motion, no reordering.
- **Tests + gate:** `policy_tests.rs` parse/global/app clusters (F17); `make test-rust`.
- **Why it matters:** >8 responsibilities, >100 LOC → the standing god-fn rule.
- **Fix direction:** extract `compile_rule` first (largest, most self-contained).
- **Labels:** modularity. **Dedup note:** matches the cataloged ~557 estimate (now 558).

#### [A4-rust-session-policy] F4 — session/mod.rs: SessionTable hot/cold field map + **no size_of pin exists today**

- **Severity:** Medium (latent perf on any careless split) · **Confidence:** High · **Refactor class:** C→B · **Dedup tag:** INCREMENT(#4421)
- **Evidence:** `SessionTable` (501–650) = **25 fields** across cleanly separable domains. `SessionEntry` (344–459) = 17 fields, stored N× in `entries: Slab<SessionRecord>`. **Grep for `size_of::<SessionEntry>` / `SessionMetadata` / `SessionKey` returns NOTHING** — the only `const _: () = assert!` in the file (203) pins the timeout-ns multiply, not any struct layout. So the catalog's "size_of-pinned territory" is an aspiration, not an enforced invariant.

  SessionTable field classification:
  - **HOT — per-packet read/write (keep co-located, D):** `entries`, `key_to_handle`, `nat_reverse_index`, `forward_wire_index`, `reverse_translated_index` (the 5 lookup structures), `timeouts` + `opening_overrides` (read in `session_timeout_ns` on install/refresh), `session_limit_active` (per-install gate).
  - **GC:** `wheel`, `last_gc_ns`, `last_pop_stats`, `epoch_counter`.
  - **HA/delta:** `deltas`, `delta_drops`, `delta_loss_pending`, `delta_drained`, `owner_rg_sessions`.
  - **Per-IP limit (gated cold):** `session_limit_src_counts`, `session_limit_dst_counts`.
  - **Config/counters:** `max_sessions`, `expired`, `create_drops`, `admission_refused`, `install_partial`, `nat_reverse_key_collisions`.
- **Proposed decomposition** (matches cataloged {ha,limit,timeout,delta} seams; code-motion of `impl SessionTable` blocks into submodules, NOT struct split of the 5 hot indices):
  - `session/limit.rs` ← `session_limit_inc/dec`, `*_map_len`, the two count maps + `session_limit_active` gate methods.
  - `session/delta.rs` ← `push_delta`, `take_delta_loss`, delta queue accessors.
  - `session/timeout.rs` ← `SessionTimeouts`, `secs_to_ns_saturating`, `app_inactivity_timeout_ns`, `session_timeout_ns`, `opening_override_for`, `set_timeouts`/`set_opening_overrides`.
  - Keep `entries`/`key_to_handle`/the 3 NAT indices/`wheel` + `remove_entry`/`restore_entry`/`index_*` in `mod.rs` (the #1855 corruption contract + #964 eager-cleanup live here and are locality-critical).
- **Hot-path preservation:** the 5 lookup structures and `wheel` MUST stay one struct (single alloc, no pointer-chase). The submodules attach `impl SessionTable` blocks (same pattern as existing lookup/install/expire.rs) — zero layout change. **Before ANY field reorder or a `SessionEntryHot/Cold` split, ADD `const _: () = assert!(size_of::<SessionEntry>() == N)` + a cargo-asm/objdump gate — none exists now.**
- **Tests + gate:** `session/tests.rs` (6,994) `*_asserts_in_debug` / capacity / limit-lifecycle clusters move with the code; `cargo test --release` for the `cfg(not(debug_assertions))` corruption-contract arms; `make test-failover` (session-sync path).
- **Why it matters:** 2,054 LOC and growing (1,900→2,054); the god-struct fuses HA/GC/limit/counter state with the 5 hot indices, and there is NO compile-time guard protecting the hot layout.
- **Fix direction:** land the size_of pin FIRST (pure safety net), then `limit.rs`/`delta.rs`/`timeout.rs` code-motion.
- **Labels:** modularity, hot-path-layout. **Dedup note:** adds the concrete hot/cold map + the missing-pin fact the catalog assumed existed.

#### [A4-rust-session-policy] F6 — nat64.rs: proposal validated; ext-hdr walker divergence is FIXED

- **Severity:** Low · **Confidence:** High · **Refactor class:** B · **Dedup tag:** INCREMENT(#4421) + STATUS-UPDATE
- **Evidence:** 2,527 LOC; fn map confirms the cataloged {state,headers,translate,icmp,checksum,frame} cluster boundaries exactly:
  - state/alloc 187–624 (Nat64Prefix/State/ReverseInfo/Match, from_snapshots*, allocate*, forward_decision)
  - release/rollback/reserve 625–825
  - **headers/frag 826–1195** (`next_frag_id`, `map_frag_id`, `ipv6_l4_offset_and_protocol`(928), `ipv6_is_non_first_fragment`(1001), fragment-header parse, `*_is_fragment_drop`)
  - translate/write 1196–1650 (`write_v6_to_v4_into`(1196=**203 LOC**), `write_v4_to_v6_into`(1424=**227 LOC**))
  - icmp-embedded 1651–2237
  - checksum 2238–2424 (`checksum16*`, `checksum16_incremental`, `adjust_l4_checksum_*_incremental`)
  - frame-build 2425–2527
  - **DIVERGENCE FIXED:** `ipv6_l4_offset_and_protocol` (928) now walks `for _ in 0..MAX_IPV6_EXT_HEADERS` and **fails closed at the bound** (#4435), explicitly "true parity … dropped by BOTH walkers" with `frame::inspect` (#4517 added the generic 0/43/60/135/139/140/253/254 + AH/frag arms). The catalog/hot-path note (line 189: "capped 0..6 vs canonical =8") is **stale**.
- **Proposed decomposition:** as cataloged. Split `write_v6_to_v4_into`/`write_v4_to_v6_into` from the RFC6052 classify only if it does not separate the incremental-checksum adjust from the byte-write it pairs with.
- **Hot-path preservation:** (1) `write_*_into` writes into a caller-provided buffer — the **UMEM copy-release invariant lives in the poll-path CALLER**, not here; the split must not move buffer ownership into nat64.rs. (2) Keep `checksum16_incremental` + `adjust_l4_checksum_*_incremental` in `checksum.rs` but ensure `write_*_into` can still inline them (same-crate `#[inline]`); do NOT introduce a `PacketBuffer` trait (the hot-path note forbids a packet-buffer abstraction). (3) `next_frag_id` uses a process-global counter — keep atomic ordering.
- **Tests + gate:** `nat64_tests.rs` (3,984) → `nat64/tests_{state,headers,translate,icmp,checksum,frame}.rs`; `make test-rust`; NAT64 end-to-end from a test host (session/hit counters) per engineering-style validation table.
- **Why it matters:** 2,527 LOC, top of the NAT64 monolith list; the module has 6 genuinely separable concerns.
- **Fix direction:** peel `checksum.rs` + `icmp.rs` first (leaf, no hot-buffer ownership), then headers/translate.
- **Labels:** modularity. **Dedup note:** corrects the stale 0..6 divergence note; confirms `Nat64Prefix.pool_index` dead-code (1d) unchanged.

#### [A4-rust-session-policy] F7 — nat/source.rs: `match_source_nat_result_for_tuple` hot god-fn (342 LOC)

- **Severity:** Medium (review-cost on the new-flow SNAT fast path) · **Confidence:** High · **Refactor class:** B (with C care) · **Dedup tag:** INCREMENT(#4409)
- **Evidence:** lines 996–1337 = **342 LOC**, single function; it is the cataloged hot new-flow SNAT matcher (`nat/source.rs::match_source_nat_result_for_tuple`). Surrounding rule predicates are already small helpers (`SourceNatRule::matches`(387=55), `scope_matches`(326), `l4_matches`(363)). The 342-LOC body does rule iteration + address/port allocation dispatch + persistent-NAT + nat64-pool + failure-reason mapping inline.
- **Proposed decomposition:** carve the body into `snat_match.rs` phase helpers off `SourceNatRule`: `select_matching_rule`, `resolve_translation(rule, tuple)`, `map_failure(reason)` — the outer fn becomes the linear-scan driver. Keep parse (`parse_source_nat_rules_with_previous`, 192 LOC cold) in `snat_rule.rs`, allocation entry points (`allocate_nat64_pool_port`, release/reserve) in `snat_alloc.rs` — matches cataloged `snat_rule/snat_match/snat_alloc.rs`.
- **Hot-path preservation:** `#[inline]`, alloc-free on the match path; `String` clone only on the cold failure branch (already the case — `SourceNatFailure::for_rule`). Do not box the rule iterator; keep the `for rule in &rules` linear scan monomorphic. The dead `source_nat_runtime_compatible` (691, catalog 1d) can be deleted in the same PR.
- **Tests + gate:** `nat/tests_source.rs` (already split, #4409 inc); new-flow SNAT end-to-end + negative-case drop; `make test-failover` (HA SNAT persistent-lease).
- **Why it matters:** 342 LOC on the packet-establishing path is the worst god-fn in NAT proper.
- **Fix direction:** extract `resolve_translation` first (the allocation dispatch bulk).
- **Labels:** modularity, hot-path-adjacent. **Dedup note:** adds the exact fn LOC the catalog's #4409 line lacked (it named source.rs at file level only).

#### [A4-rust-session-policy] F12 — screen/extract.rs: `extract_screen_info` single-fn file (348 LOC)

- **Severity:** Low · **Confidence:** High · **Refactor class:** B · **Dedup tag:** INCREMENT(codex-171-8)
- **Evidence:** the entire production file is one fn `extract_screen_info` (52–399 = **348 LOC**, grown from cataloged ~305). It parses IPv4 header + options (LSRR/SSRR), IPv6 + ext-hdr chain (RH0/RH1 source-route), fragment fields, and TCP header into `ScreenPacketInfo` — per screened packet.
- **Proposed decomposition:** `extract_v4(pkt) -> …`, `extract_v6(pkt) -> …`, `extract_source_route_v4/v6`, `extract_tcp_fields` — the cataloged "IPv4/IPv6/source-route/TCP helper parsers." Outer fn dispatches on family.
- **Hot-path preservation:** all `#[inline]`, same-crate; this is a per-first-packet parser — keep constant-offset reads (frame/inspect narrowing gotchas), no allocation. Do not read past declared lengths (fail-closed like the frame parser).
- **Tests + gate:** `screen/tests.rs` extract/source-route clusters; `make test-rust`; source-route + fragment screens end-to-end.
- **Why it matters:** a 348-LOC single-responsibility-per-family parser is a clean, low-risk split.
- **Fix direction:** split by family first.
- **Labels:** modularity. **Dedup note:** matches codex-171-8; LOC updated 305→348.

#### [A4-rust-session-policy] F14 — afxdp/session_glue/mod.rs: low-cohesion glue module + 2 god-fns (NEW)

- **Severity:** Medium · **Confidence:** High · **Refactor class:** B · **Dedup tag:** NEW (only tests.rs mass cataloged)
- **Evidence:** 1,277 LOC spanning ≥6 responsibilities: forwarding-resolution lookups (`lookup_forwarding_resolution_for_session*`, `populate_egress_resolution`), worker-command apply (`apply_worker_commands`, 552=**179 LOC**), TCP-RST teardown (`should_teardown_tcp_rst`/`teardown_tcp_rst_flow`), flow cancellation (`cancel_queued_flow*`/`recycle_cancelled_prepared`/`*_matches_flow`), shared-session materialize (`materialize_shared_session_hit`), lo0/DSCP session republish/purge (`republish_local_delivery_sessions_for_lo0_filter`, `purge_sessions_for_input_dscp_filter_revalidation`(326=120)), and HA resolution (`resolve_flow_session_decision`, 1013=**221 LOC / 19 parameters**, `enforce_session_ha_resolution`, `redirect_session_via_fabric_if_needed`). The name "session_glue" is itself the smell.
- **Proposed decomposition:** `session_glue/resolve.rs` (resolve_flow_session_decision + lookup_forwarding_resolution* + enforce/redirect HA), `session_glue/commands.rs` (apply_worker_commands + replicate_*), `session_glue/teardown.rs` (tcp_rst + cancel/recycle/matches_flow), `session_glue/revalidate.rs` (lo0/DSCP republish+purge+delete_terminal_filtered). `resolve_flow_session_decision`'s 19 params: bundle the shared refs (already partly done via `SharedSessionRefs`) and pass a `SessionResolveCtx` for the config/HA/neighbor cluster to get under the 8-param rule.
- **Hot-path preservation:** `resolve_flow_session_decision` runs per new flow; keep it monomorphic. The doc-comment itself notes **cargo-asm 0.1.16 cannot parse this crate's symbols**, so the empirical gate is smoke + `test-failover` (state this explicitly in the split PR — the standard cargo-asm-diff gate is unavailable here).
- **Tests + gate:** `session_glue/tests.rs` (5,587) clusters by the four new modules; `make test-failover` (this is the HA session-resolution core) + `make test-ha-crash`.
- **Why it matters:** a 19-param 221-LOC function on the HA new-flow path with no cargo-asm gate is both a review hazard and a refactor hazard; the module is the lowest-cohesion one in the group.
- **Fix direction:** `teardown.rs` + `revalidate.rs` first (cleanest seams), then the `resolve.rs`/`commands.rs` split with the ctx-struct param reduction.
- **Labels:** modularity, hot-path-adjacent, param-cluster. **Dedup note:** NEW — catalog only listed session_glue/tests.rs (5,587) as a test-split.

#### [A4-rust-session-policy] F15 — filter/compiler.rs: `parse_term` (426 LOC)

- **Severity:** Low · **Confidence:** High · **Refactor class:** B · **Dedup tag:** INCREMENT(agy-171-17)
- **Evidence:** `parse_term` (526–951 = **426 LOC**, matches cataloged 425). Cold compile path; lowers one config filter term to a `FilterTerm` (address vecs, protocol bitmap, port matchers incl. `*-except`, DSCP bitmap, tcp-flags mask/forbidden, icmp-type/code, flex-match, three-color-policer link, all the #2400/#2505/#2506/#2622/#3367/#3406 fail-closed markers). `parse_filter_state_with_three_color_preserving` (54=285) is the other large cold fn.
- **Proposed decomposition:** cataloged `filter/compile/{parse,validate,link}.rs`: `parse.rs` ← per-match-field parsers (`parse_address_scope`, `parse_port_scope`(pos+except), `parse_dscp`, `parse_tcp_flags`, `parse_icmp`, `parse_flex`), `validate.rs` ← the SnapshotIntegrityError-raising checks, `link.rs` ← counter/policer runtime linking. `parse_term` becomes a ~50-LOC driver.
- **Hot-path preservation:** N/A (compile). Only invariant: the fail-closed `SnapshotIntegrityError` raises must stay on the SAME code paths (they gate the reconcile preflight) — pure code-motion, no reordering of the raise-vs-drop decisions.
- **Tests + gate:** `filter/tests.rs` term/flex/tcp/icmp/dscp clusters (F17); `make test-rust`.
- **Why it matters:** 426 LOC / many responsibilities on the config-compile path.
- **Fix direction:** peel per-field parsers into `parse.rs`.
- **Labels:** modularity. **Dedup note:** matches agy-171-17; LOC unchanged.

#### [A4-rust-session-policy] F17 — Test-file splits: concrete cluster→module mapping (top two)

- **Severity:** Low · **Confidence:** High · **Refactor class:** A (mechanical) · **Dedup tag:** INCREMENT(codex-171-29)
- **Evidence:** both largest files are a single flat `mod tests` (no sub-mod grouping). `filter/tests.rs` = 8,330 LOC / 152 tests; `policy_tests.rs` = 7,161 / 180 tests. Test-name prefix histograms give clean clusters.
  - **filter/tests.rs → mirror the production engine/ split:**
    - `filter/engine/matching.rs`-adjacent ← flex(13), tcp(7), icmp(9), dscp(6), protocol(9), port/prefix/empty(≈12) match tests (~56).
    - `filter/engine/eval.rs`-adjacent ← fallthrough(8), pbr(6), interface(8), input(6), non-routing(4), evaluate(9) (~41).
    - `filter/engine/tx_selection.rs`/`cache_sensitive.rs`-adjacent ← cached(3), three-color(4), per(3), flow(3), extra(3) (~16).
    - `filter/compiler.rs`-adjacent ← term(12), missing_filter_ref(3), source/destination address(≈5) (~20).
  - **policy_tests.rs → mirror the F1 policy/ split:**
    - `policy/tests_apps.rs` ← app(16) (AppCatalog/CompiledApplications/parse_applications).
    - `policy/tests_global.rs` ← global(12) (GlobalZoneScope / global-policy).
    - `policy/tests_evaluate.rs` ← evaluate(4), policy(6), icmp(5), frag(2), deny/permit(≈3) (~20).
    - `policy/tests_nat.rs` (or fold to evaluate) ← nat(9).
    - `policy/tests_parse.rs` ← parse(1), book(1) + zone/address-set parse tests.
- **Proposed decomposition:** land the production split (F1/F15) first, then move each test cluster to a per-file `mod tests` next to the code it exercises (the project's `tx/`/`cos/` pattern).
- **Hot-path preservation:** N/A.
- **Tests + gate:** `make test-rust` before/after must show identical test count; pure code-motion.
- **Why it matters:** 8,330-LOC flat test files are the review-cost tail; splitting is mechanical once the production seams land.
- **Fix direction:** do the test split in the SAME PR as each production split (engineering-style: refactor with the change, not after).
- **Labels:** test-split, modularity. **Dedup note:** adds the concrete cluster map codex-171-29 lacked.

---

#### [A5-rust-control] A5-F1 — event_stream/codec.rs: RT_FLOW wire codec has no named-offset SSOT; 196-LOC encoder god-fn

- **Title:** RT_FLOW binary codec hand-writes 69 magic byte-offsets across 4 encoders with zero named offset constants
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** (B) REQUIRES GUARDRAILS — wire-format/endianness cohesion; byte-identical output must be proven
- **Dedup tag:** NEW
- **Evidence:** `codec.rs` (1165 LOC). `impl EventFrame` spans 263–986 (~723 LOC) with 4 encoders that each rebuild the 152-byte layout by hand:
  `encode_session_close_rt_flow` (565–761, **196 LOC**), `encode_session_open` (265–449, 184), `encode_session_close` (449–565, 116), `encode_session_create_rt_flow` (761–849, 88), plus `encode_dataplane_event` (61) and `decode_dataplane_event` (64). Grep counts **69** `base + <literal>` offset writes and **0** `const OFF_*` definitions:
  ```rust
  buf[base..base + 8].copy_from_slice(&close_unix_ns.to_le_bytes());     // [0:8]
  write_ip_16(&mut buf, base + 8, src_ip);                               // [8:24]
  buf[base + 40..base + 42].copy_from_slice(&src_port.to_be_bytes());    // [40:42] BE
  buf[base + 44..base + 48].copy_from_slice(&created_subsec_nanos...);   // [44:48] repurposed
  buf[base + 48..base + 50].copy_from_slice(&ingress_zone_id.to_le_bytes());
  ```
  Offset 44 is `policy_id` on some frames and `created_subsec_nanos` on the close frame (#2853); offsets 128/132/135/144:152 are additive blocks (#2615/#2520/#2508/#2749). The map lives ONLY in comments + `event_stream/README.md` — nowhere in code as a single source. `encode_session_close_rt_flow` alone takes **24 positional args** (well past the >8-param refactor cue).
- **Responsibility count / callers:** 1 module, ~7 encode/decode responsibilities. Encoders called from `afxdp/event_emit.rs` and `event_stream/mod.rs` (`emit_session_close_rt_flow`/`emit_session_create_rt_flow`); decoder consumed on the Go side via the mirrored `dataplane.Event` layout.
- **Proposed decomposition:** (1) A `codec/layout.rs` (or top-of-file) block of named `const OFF_TIMESTAMP: usize = 0; OFF_SRC_IP = 8; OFF_NAT_SRC_IP = 72; OFF_POLICY_ID = 44; OFF_APP_ID = 132; OFF_INGRESS_IFINDEX = 128; OFF_COS_BLOCK = 144;` … as the single offset SSOT, with `const _: () = assert!(OFF_COS_BLOCK + 8 == SECURITY_EVENT_PAYLOAD_SIZE);` guards. (2) Extract the shared 5-tuple/NAT/zone/appid writer into one `write_rt_flow_common(buf, base, tuple…)` helper both the close and create encoders call, collapsing each 196/88-LOC encoder. (3) Group the encoders into a `codec/encode.rs` and the ~24-arg signatures into a `RtFlowCloseFields` context struct. Keep encode + decode + offset consts in the SAME module tree so the layout can't fork.
- **Hot-path preservation analysis:** Cold path — emitters fire per deny/drop/session-close, not per packet (each already does a wall-clock read per emit, #2470). No `#[inline(always)]` hot-loop code here. Guardrail is CORRECTNESS not latency: a fixed-`[u8;256]` scratch buffer is used (no heap), and named consts + a shared writer must produce a **byte-identical** frame. `codec_tests.rs` (995 LOC) + the `protocol_wire_v1.json` fixture is the fail-on-revert gate; extend it to pin each offset const against a golden frame.
- **Tests + gate:** `event_stream/codec_tests.rs` moves with the module; add `const _` offset asserts + a golden-frame test per message type. Reverting the shared writer to divergent literals must go RED.
- **Why it matters:** Engineering-style principle #3 ("one source of truth for every formula"). Four encoders each re-deriving the same 152-byte map is exactly the drift class that #2853 (offset-44 reuse) and #3056/#3058 (policy-id slot moves) already had to reason about frame-by-frame. A future additive field that lands on the wrong offset in one of the four encoders is silent wire corruption seen only by whichever consumer reads that frame type.
- **Fix direction:** Named offset consts + shared tuple writer + context-struct for the wide encoders; no wire change.
- **Labels:** wire-format, SSOT, god-function, event-stream
- **Dedup note:** codec.rs was NOT in the dedup catalog (event_stream/mod.rs is codex-173-15; codec.rs is fresh). Distinct from that finding.

#### [A5-rust-control] A5-F2 — coordinator/status.rs: status-projection grab-bag with a 201-LOC worker-snapshot god-fn

- **Title:** `coordinator/status.rs` fuses ~30 status projections; `worker_runtime_snapshots` is a 201-LOC wide-projection god-fn
- **Severity:** Low–Medium
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL/SAFE
- **Dedup tag:** NEW
- **Evidence:** `status.rs` (1195 LOC) is a single `impl Coordinator` block of operator-status methods (its own docstring says it was split out of `mod.rs` "to keep the gRPC/HTTP status methods in one place"). Largest: `worker_runtime_snapshots` (619–820, **201 LOC**), `wg_tunnel_statuses` (820–969, 149), `source_nat_pool_statuses` (56), `cos_statuses` (28), `cos_active_flow_counts`, `filter_term_counters`, `neighbor_resolver_counters`, `overlay_shared_cos_queue_lease_statuses` (43), plus ~20 small counter reads. `worker_runtime_snapshots` is a flat `.map()` over workers that inlines: runtime-atomics snapshot, cold-path seqlock snapshot (#1621), panic-message lookup, per-field WorkerRuntimeStatus population, histogram/window projection — one function doing 5 sub-projections.
- **Responsibility count / callers:** 1 module, ~6 status domains (worker, wg-tunnel, cos, nat-pool, neighbor, filter). Consumed by `server/helpers.rs::refresh_status` → control-socket STATUS response → Go `ProcessStatus`.
- **Proposed decomposition:** `coordinator/status/{worker,wg,cos,nat,neighbor,filter}.rs` per-domain `impl` blocks (mirrors how `protocol/` was #1325-split by domain). Within worker.rs, peel the cold-path seqlock projection and the histogram/window projection into `fn project_cold_path(cold, failed) -> …` and `fn project_worker_windows(w) -> …` helpers so `worker_runtime_snapshots` becomes a thin `.map(build_worker_status)`.
- **Hot-path preservation analysis:** Fully cold — status poll runs 1/s (control-socket contention rule: single `Status()` call per scrape; this must stay one pass, no new per-family control-socket fetch). Pure reads of ArcSwap/atomics; splitting into per-domain files adds no allocation and no dispatch. The one mutating method the docstring flags (`drain_session_deltas`) stays wherever it lands; no ordering change.
- **Tests + gate:** the `equal_flow_overlay_*` / `flow_fair_flow_count_overlay_*` inline tests already in status.rs move with `overlay_shared_cos_queue_lease_statuses`. Add a `WorkerRuntimeStatus` golden-projection test pinning the never-sampled vs sampled vs failed cases (the #1621 wire-omitempty contract) so the helper extraction stays byte-identical.
- **Why it matters:** 1195 LOC and climbing; the module is a natural per-domain split and the 201-LOC projection is exactly the ">100-line function → context-struct/helper" cue. It also guards the #1621 omitempty wire contract, which is easy to break in a monolithic map closure.
- **Fix direction:** per-domain `status/*.rs` + helper extraction inside worker projection.
- **Labels:** status-projection, god-function, coordinator
- **Dedup note:** status.rs is fresh (not cataloged). Do not confuse with `server/helpers.rs::refresh_status` (codex-171-10, F-INC below), which is the *consumer* of these projections.

#### [A6-go-config] F1 — `runUniformGates`: 1,659-LOC single-function ordered-gate monolith

- **Title:** `compiler_uniformgates.go` is one 1,659-LOC function running ~78 fail-open gates in behavior-significant source order
- **Severity:** Medium (reviewability; a 1.6k-LOC single fn is unreviewable as a unit)
- **Confidence:** High
- **Refactor class:** (B) REQUIRES GUARDRAILS — the guardrail already exists
- **Dedup tag:** NEW (file uncataloged; FRESH per brief)
- **Evidence:**
  ```
  27:func runUniformGates(tree *ConfigTree, cfg *Config, opts compileOpts) error {
  40:  if err := validateClassOfServiceSchedulerMapRefsStrict(...); err != nil { ... }
  56:  if err := validateClassOfServiceLossPriorityStrict(...);   err != nil { ... }
  74:  if err := validateClassOfServiceForwardingClassQueueStrict(...); ...
  ...  (78 total `if err := validate…Strict(…)` invocations, each with an
       8–12 line comment block, run head-to-tail; NO early return except the
       first failing gate on the strict path)
  1659:}  // EOF
  ```
  Header comment is explicit: "the FIRST failing gate wins the returned error slot
  (invariant #6)"; on the tolerant path "all gates run and their warnings accumulate
  in this exact sequence (invariant #7)"; "This is a verbatim contiguous lift."
- **Callers:** single caller `compileExpanded` (compiler.go:1986, the P6b phase between
  P6a fold-accumulator and the P7 tail).
- **Proposed decomposition:** convert the straight-line body to a **table-driven
  dispatch** that preserves order by construction:
  ```go
  type uniformGate struct {
      name      string
      run       func(cfg *Config) error       // or (tree,cfg) for the 1 AST gate
      tolerant  func(opts compileOpts) bool    // per-gate lenient flag selector
  }
  var uniformGates = []uniformGate{ {"cos-scheduler-map-ref", …, optsLenientSchedulerMapRef}, … } // 78 rows
  func runUniformGates(tree, cfg, opts) error {
      for _, g := range uniformGates {
          if err := g.run(cfg); err != nil {
              if g.tolerant != nil && g.tolerant(opts) { cfg.Warnings = append(cfg.Warnings, err.Error()); continue }
              return err
          }
      }
      return nil
  }
  ```
  The slice literal is the SSOT ordering; the 78 comment blocks become row comments.
  File shrinks from a 1.6k-LOC function to a ~200-line table + the small loop. The
  gate bodies (`validate…Strict`) already live in the strict-split files — nothing moves.
  Alternatively (more conservative, zero-behavior): mechanically bucket the 78 calls
  into `runUniformGates_{cos,policy,zone,screen,chassis,nat,routing,…}(cfg,opts)`
  sub-runners called in order from a thin `runUniformGates`. Same golden-test gate.
- **Hot-path preservation:** N/A — commit/commit-check/load path, not per-packet. Zero
  latency concern; this is pure reviewability.
- **Tests + gate:** **already pinned** — `compile_golden_4406_test.go` is a
  golden-output gate over the full gate run, and `strict_gate_wiring_canary_test.go`
  asserts each gate is wired. Any reorder or dropped gate fails these. This is what
  makes F1 class-B-with-guardrail rather than risky. `make test-go` runs both.
- **Why it matters:** by the project's own modularity rule (`docs/engineering-style.md`:
  ">3,000 LOC → split before adding logic; >100-LOC fn is a refactor cue") a 1,659-LOC
  single function is the single worst god-function in the group. The NEXT gate added
  here should land on the table, not extend the straight-line body.
- **Fix direction:** table-driven `[]uniformGate`; rows in current source order; lenient
  flag as a per-row selector so invariant #6/#7 are structural, not incidental.
- **Labels:** monolith, god-function, order-sensitive, guardrail-exists
- **Dedup note:** file not in the catalog (it is the *destination* of the compileExpanded
  split — the gate run was lifted out of the 2,435-LOC compileExpanded into this file).
  Genuinely NEW as a standalone finding.

#### [A6-go-config] F2 — `ValidateConfig` (compiler_validate_warn.go): 1,534-LOC god-function, half-carved

- **Title:** `ValidateConfig` is a 1,534-LOC inline warning-accumulator whose tail already
  delegates to ~13 helpers but whose head does ~20 domains inline
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL
- **Dedup tag:** INCREMENT(codex-171-20) — the catalog estimated "~1,357"; **measured
  current LOC is 1,534** (lines 51–1585)
- **Evidence:** the fn splits cleanly into two halves:
  - **Inline head (~lines 55–1440):** ~20 warning domains computed directly with
    `warnings = append(warnings, fmt.Sprintf(...))` + inline loops — in order:
    ebpf-note, collect-valid-zone-names, collect-valid-address-book-entries,
    application-port/protocol, policy match, NAT zone-refs, static-NAT zone-refs,
    screen refs, address-book CIDR/IP format, static-route CIDR, DNAT-pool refs,
    SNAT-pool refs, zone-interface refs, scheduler refs, routing-instance interface
    refs, chassis-cluster fabric, strict-vip-ownership/VRRP, IPsec Phase-2 ESP,
    sampling.
  - **Delegating tail (~lines 1442–1583):** already-extracted helpers, e.g.
    `validateDefaultPolicyLogWarnings`, `validatePolicyLogInertOnDenyWarnings`,
    `validateJunosHostDirectDeliveryWarnings`, `validateInterfaceParityWarnings`,
    `validateDHCPRelayParityWarnings`, `validateHostInboundMulticastWarnings`.
- **Callers:** `ValidateConfig` is the package's public warning entry point (exported).
- **Proposed decomposition:** apply the tail's established pattern to the head — extract
  each `// Validate X` block into `validateXWarnings(cfg *Config) []string`, grouped into
  new files mirroring codex-171-20: `compiler_warn_{application,policy,nat,addressbook,
  routing,cluster,ipsec}.go`; `ValidateConfig` becomes a thin ordered fan-in appending
  each helper's slice. **Pure vs stateful:** the tail helpers are all **pure** `func(cfg)`
  and recompute what they need. The head computes two shared sets — `validZoneNames` and
  the valid address-book entry set — near the top and reuses them across domains; the
  clean move is to make each extracted helper recompute (matches the pure-tail convention)
  OR pass a small `warnCtx{zoneNames, addrBookEntries map[string]bool}` to the ~6 helpers
  that need it. Recompute is simpler and O(zones)/O(entries) — negligible at commit time.
- **Order note:** warning ORDER is observable (operators read the top warning first). Keep
  the fan-in sequence identical to today's inline order.
- **Hot-path preservation:** N/A (commit-time warning path).
- **Tests + gate:** `schema_validate_test.go` + the many domain `*_test.go` that assert
  specific warning strings; a golden-warning corpus test would harden the order. `make
  test-go`.
- **Why it matters:** 3,330-LOC file, half of it one function; the extraction template is
  already present in the same file (the tail), so this is low-risk mechanical debt.
- **Fix direction:** mirror the tail — one `validateXWarnings(cfg)` per head domain.
- **Labels:** god-function, mechanical, warning-order
- **Dedup note:** cataloged as codex-171-20 OPEN; this adds the measured 1,534 LOC, the
  ordered domain list, and the pure-vs-stateful shared-set detail requested.

#### [A6-go-config] F3 — compiler.go: `compileExpanded` DONE; residual bulk is the 98-field `compileOpts` struct + a byte-identical duplicated lenient literal

- **Title:** compiler.go's 2,110 LOC is dominated by a 1,509-LOC `compileOpts` struct
  declaration; the 98-field lenient literal is duplicated verbatim in two constructors
- **Severity:** Low-Medium (drift risk on the duplication; the struct size itself is benign)
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL
- **Dedup tag:** STATUS-UPDATE (agy-171-09 compileExpanded) + INCREMENT(ps-036-cohort2 F-044)
- **Evidence:**
  - `compileExpanded` (compiler.go:1986–2110) is now a **124-LOC orchestrator**: runs
    AST pre-walks → `compileSections(tree,cfg,opts)` (compiler_dispatch.go) →
    `runUniformGates(tree,cfg,opts)` → `SchemaValidate` → P7 tail. The catalog's
    "🟡 PARTIAL — now 2,110 LOC" conflates FILE LOC with FN LOC: the **function** is
    down from 2,435 → 124 LOC. The compileExpanded god-fn is effectively **DONE**.
  - `type compileOpts struct` spans **lines 44–1553 (~1,509 LOC)** — ~98 lenient flags,
    each with a paragraph comment. This declarative struct is the file's real mass.
  - The lenient literal is duplicated:
    ```
    CompileConfigLenient        (1573–1706): 98 `field: true,` rows
    CompileConfigForNodeLenient (1822–1922): 98 `field: true,` rows
    diff of the two field-name sets → IDENTICAL (byte-for-byte the same field set)
    ```
- **Callers:** `CompileConfigLenient` / `CompileConfigForNodeLenient` are the two tolerant
  entry points (load / peer-sync).
- **Proposed decomposition:**
  1. Extract the shared literal: `func defaultLenientOpts() compileOpts { return compileOpts{ …98 rows… } }`; both constructors call it (ForNode additionally sets `nodeID`). Kills the F-044 drift risk — a new lenient flag can no longer be added to one path and forgotten in the other.
  2. Optionally move the struct itself to `compiler_opts.go` (mechanical) so compiler.go holds only the entry points + orchestrator (~600 LOC).
- **Hot-path preservation:** N/A.
- **Tests + gate:** `dual_ast_differential_test.go` exercises both compile paths; add a
  test asserting `CompileConfigLenient` and `CompileConfigForNodeLenient` produce the same
  lenient posture (they must, per the SyncApply doctrine). `make test-go`.
- **Why it matters:** two 98-field literals WILL drift; the engineering-style doc's first
  principle #3 ("one source of truth for every formula") applies directly.
- **Fix direction:** `defaultLenientOpts()` helper first (correctness); struct-file move
  second (cosmetic).
- **Labels:** duplication, drift-risk, dumping-ground-struct, status-update
- **Dedup note:** F-044 cataloged the 79-field figure; current count is 98. compileExpanded
  status corrected from PARTIAL → effectively DONE at fn level.

#### [A6-go-config] F4 — `compileProtocols`: 783-LOC god-function (uncataloged file)

- **Title:** `compiler_protocols.go::compileProtocols` parses LLDP/OSPF/BGP/ISIS/RIP/RA
  inline in one 783-LOC nested switch
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL
- **Dedup tag:** NEW (compiler_protocols.go not in catalog)
- **Evidence:**
  ```
  12:func compileProtocols(node *Node, proto *ProtocolsConfig) error {
  13:    switch child.Name() {
  14:    case "lldp":   … (LLDP block, ~30 LOC inline switch)
  46:    case "ospf":   … (OSPF: nested area/interface/authentication/bfd switch, ~150 LOC)
  199:   case "bgp":    … (BGP: local-as/router-id/cluster-id/neighbor/group, big)
  …    isis / rip / (router-advertisement is already a separate fn at 795)
  795:} // end compileProtocols
  ```
  Each `case` is a self-contained per-protocol parser — no cross-protocol state.
- **Callers:** `compileSections`/dispatch.
- **Proposed decomposition:** one helper per protocol — `compileOSPF(node,*OSPFConfig)`,
  `compileBGP`, `compileISIS`, `compileRIP`, `compileLLDP` — in new
  `compiler_protocols_{ospf,bgp,isis,rip}.go`; `compileProtocols` becomes a ~30-LOC
  keyword dispatch. `compileRouterAdvertisement` (already extracted at :795) is the model.
- **Invariants at risk:** dual AST shape (hierarchical `protocols ospf { … }` vs flat-set
  `set protocols ospf area … interface …`) and bracket-list `export [ a b c ]` via
  `firewallMatchValues` (line ~75, `proto.OSPF.Export = append(..., firewallMatchValues(child)...)`
  — #2419 multi-value handling). Each extracted helper must keep reading both `child.Keys[1:]`
  and `child.Children`.
- **Hot-path preservation:** N/A.
- **Tests + gate:** `parser_routing_test.go` (96 tests) + `routing_export_ref_test.go`;
  `make test-go`.
- **Why it matters:** largest uncataloged god-function in the group after runUniformGates.
- **Fix direction:** per-protocol extraction mirroring compileRouterAdvertisement.
- **Labels:** god-function, mechanical, dual-ast, multi-value-#2419
- **Dedup note:** NEW.

#### [A6-go-config] F5 — compiler_nat.go 4-file seam validated (covered-by-catalog + carry-list)

- **Title:** the cataloged `compiler_nat_{source,destination,static,validate}.go` split
  holds against current code
- **Severity:** Medium (size) — tracked
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL
- **Dedup tag:** INCREMENT(ps-011 / agy-171-10) — validates the seam + names the #2419 carry
- **Evidence (fn boundaries confirm the 4 clean cut lines):**
  ```
  compileNAT(831) compileNAT64(956)                              → compiler_nat.go core (dispatch)
  compileNATSource(1342, 521 LOC) parseSourcePoolPortRange
    applyDeterministic{Keys,Children,Host} appendPoolAddresses    → compiler_nat_source.go
  compileNATDestination(1883, 227) parseDNATPoolAddress
    appendDNATPortRange parseDNATPortList                          → compiler_nat_destination.go
  compileNATStatic(2358, 171) staticNATMappedPortFromKeys
    staticNATRoutingInstanceFromKeys resolveStaticNATThenPrefix*  → compiler_nat_static.go
  validatePoolUtilizationAlarm(49) validateNATHostMaskStrict(287,249)
    validateNPTv6Strict(536,234) validateNAT64PrefixStrict(770)
    validateStaticNATThenTargetStrict(2323)                       → compiler_nat_validate.go
  ```
- **Multi-value / shared helpers the split MUST carry (do not orphan):** `parseZoneList`
  (990), `parseNATMatchScopes` (1045), `collectNATScopes` (1093), and the
  `applyNATFromScope/applyNATToScope/applyStaticNATFromScope` trio (1114–1157) are shared
  by source+destination+static — they belong in the retained `compiler_nat.go` core (or a
  `compiler_nat_scope.go`), NOT in any one domain file. `expandAddressRange` (1183) is
  source+dest shared. These reference the same dual-AST + bracket-list conventions.
- **Order note:** `validateNATHostMaskStrict` → `validateNPTv6Strict` →
  `validateNAT64PrefixStrict` run as uniform gates (F1) in that order; moving them to
  `_validate.go` must not change the order they are *called* from `runUniformGates`.
- **Hot-path preservation:** N/A.
- **Tests + gate:** `compiler_nat_host_mask_test.go`, `compiler_nptv6_test.go`, and the NAT
  arm of `parser_security_test.go`; `make test-go`.
- **Why it matters:** 2,529 LOC, four independent 170–520-LOC compilers; the seam is clean.
- **Fix direction:** the cataloged 4-file split, with a `_scope.go` for the shared scope helpers.
- **Labels:** monolith, mechanical, nat, multi-value-#2419
- **Dedup note:** ps-011/agy-171-10 OPEN; adds the shared-scope-helper carry-list.

#### [A6-go-config] F6 — compile-dispatch god-functions across five mid-band files

- **Title:** the `compile<Domain>` dispatchers are nested-switch god-functions:
  `compileSystem`(536), `compileInterfaces`(535), `compileClassOfService`(509),
  `compileFirewall`(319)+`compileFilterFrom`(222), `compileChassis`(300)
- **Severity:** Medium (each) — Low individually, Medium as a pattern
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL
- **Dedup tag:** mixed — `compileSystem`/`compileChassis` INCREMENT(codex-171-22, file split
  already proposed); `compileInterfaces`/`compileClassOfService`/`compileFirewall` are NEW
  fn-level god-functions in mid-band files not carrying a fn-level catalog entry
- **Evidence:** god-function census (awk fn-LOC, threshold 150), full table under Inspection
  log. Each is a `switch child.Name() { case … }` that parses an entire subtree inline;
  every `case` block is independently extractable to `compile<Domain><Child>(child, dst)`.
- **Callers:** `compileSections` dispatch.
- **Proposed decomposition:** per-child extraction. `compiler_class_of_service.go` already
  shows the pattern (`parseCoSInterfaceUnitBody` etc. peeled from the switch); apply the
  same to the OSPF-style inner switches. codex-171-22's `compiler_system_{core,login,
  dataplane,shared_umem,snmp,schedulers,chassis}.go` file split IS the mechanism for
  compileSystem/compileChassis.
- **Invariants at risk:** dual AST shape + bracket-list #2419 in every extracted arm
  (interfaces `family inet address … vrrp-group [ … ]`; firewall `from source-address
  [ … ]` via `firewallMatchValues`); `parseVRRPGroups` (237) already carries the VRRP
  bracket handling and must stay whole.
- **Hot-path preservation:** N/A.
- **Tests + gate:** `parser_system_test.go`, `parser_cluster_test.go`,
  `parser_class_of_service_test.go`, `vrrp_track_test.go`; `make test-go`.
- **Why it matters:** systematic monolith creep in the compile layer; the fix is uniform.
- **Fix direction:** per-child helper extraction; land with the codex-171-22 file split
  where one exists.
- **Labels:** god-function, mechanical, dispatch-switch, dual-ast
- **Dedup note:** partial catalog overlap (system/services/chassis); interfaces/cos/firewall
  fn-level god-fns are the NEW contribution.

#### [A6-go-config] F7 — Test-file monoliths: parser_security_test.go (5,805 / 114 tests)

- **Title:** the three largest parser test files mix unrelated domains in one `package config` test file
- **Severity:** Low (review-cost, not correctness)
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL
- **Dedup tag:** NEW (Go-side analog of the cataloged Rust test-file splits codex-171-29)
- **Evidence:** `parser_security_test.go` — 114 `func Test…` spanning IPsec(12),
  Firewall(12), Policy(11), Flexible-match(9), Screen(8), NAT(source/DNAT/NPTv6/static),
  Route, Address-book. `parser_ast_test.go` 5,586/122 tests; `parser_routing_test.go`
  3,936/96 tests.
- **Proposed decomposition:** split by domain next to the production seams —
  `parser_ipsec_test.go`, `parser_firewall_test.go`, `parser_policy_test.go`,
  `parser_screen_test.go`, `parser_nat_test.go` (mirrors compiler_nat 4-file seam),
  `parser_flexmatch_test.go`. Same-package, pure `mv` of `func Test…` blocks; zero logic
  change. Engineering-style doc calls this out: ">200 tests across unrelated subjects →
  colocate."
- **Hot-path preservation:** N/A.
- **Tests + gate:** the tests ARE the gate; `make test-go` must stay green (no test dropped).
- **Why it matters:** 5.8k-LOC test files are the review-cost tail; splitting them next to
  the production files they exercise makes a domain change reviewable.
- **Fix direction:** mechanical per-domain `mv`.
- **Labels:** test-monolith, mechanical
- **Dedup note:** Go-side; codex-171-29 covered only Rust test files.

#### [A7-go-dpmgr] F-A7-1 — `compileZones` 931-LOC god-function fuses five unrelated actuation domains

- **Severity**: HIGH (review-cost + change-risk; interface bring-down is a fail-open surface)
- **Confidence**: HIGH
- **Refactor class**: **B (requires guardrails)** — touches networkd file-gen + device-map skip + protected-set (#1922) bring-down
- **Dedup tag**: **NEW** (fresh file, not in codex-171/173 catalog)
- **Evidence**: `pkg/dataplane/compiler_iface.go` — `compileZones(dp, cfg, result)` spans L249→L1180 (next fn `applyTunnelHostInbound` at 1180) = **931 LOC**, one function. Internal phases (from in-body comments):
  ```
  L249  build iface→routing-table map from RoutingInstances (+ forwarding-instance skip)
  ~     zone iteration: host-inbound system-service/protocol flags, deferred XDP attach set,
        tunnel POINTOPOINT redirect_capable/tx_ports exclusion, HOST_INBOUND_GRE auto-add
  ~     per-interface networkd .link/.network gen: RETH (config-only, RedundantParent),
        VRRP link-local base (169.254.RG.NODE/32), VLAN units, sub-interfaces
  ~     fabric bond .netdev/.network (skip LocalFabricMember IPVLAN)
  ~     bridge-domain .netdev/.network + BridgeMaster on VLAN members
  L~    unmanaged-interface discovery + bring-down (ActivationPolicy=always-down),
        #1922 Item-4 protected set (fxp0/mgmt lifeline never stripped)
  ```
  Responsibility count: **5** (zone/host-inbound compile · networkd file-gen · fabric bond gen · bridge-domain gen · unmanaged bring-down). Caller: `CompileConfig` (compiler.go L173).
- **Proposed decomposition** (same package `dataplane`, mechanical extraction of phases into helpers called by a thin `compileZones` orchestrator):
  `compile_iface_zones.go` (zone/host-inbound flags + XDP-defer set) ·
  `compile_iface_networkd.go` (per-iface .link/.network incl. RETH/VRRP/VLAN) ·
  `compile_iface_fabric.go` (fabric bond netdev) ·
  `compile_iface_bridge.go` (bridge-domain gen + BridgeMaster) ·
  `compile_iface_unmanaged.go` (discovery + protected-set bring-down).
- **Hot-path preservation**: NOT per-packet (commit-time compile). Guardrails: (i) the unmanaged bring-down phase reads the #1922 protected set and the **device-map leave-alone skip** (see CLAUDE.md §9.6) — the extracted `compile_iface_unmanaged.go` MUST preserve "SKIP unmapped NICs under leave-alone" and "never strip fxp0/mgmt lifeline"; a naive split that reorders discovery-before-protected-set is fail-open (strands mgmt). (ii) populate-before-clear ordering ("write new keys first, then delete stale") must stay within the zone-map phase.
- **Tests + gate**: `compiler_test.go`, `proxyarp_test.go`, device-map tests in `pkg/daemon`; `make test-go`. Any interface-bring-down change also needs `make test-failover` (RETH members).
- **Why it matters**: 931 LOC in one function is unreviewable; the bring-down logic is a security boundary (unconfigured-path leak) buried under 700 lines of networkd string-building.
- **Fix direction**: extract the 5 phases behind a thin orchestrator; keep protected-set + device-map skip co-located in the bring-down helper.
- **Labels**: refactor, dataplane-compiler, class-B, fail-open-adjacent
- **Dedup note**: not previously flagged; `pkg/config` compiler splits are cataloged but this is the *dataplane-side* compiler.

#### [A7-go-dpmgr] F-A7-2 — `applyHelperStatusLocked` 483-LOC god-function (validate cataloged 6-file seam)

- **Severity**: HIGH
- **Confidence**: HIGH
- **Refactor class**: **B (requires guardrails)** — ctrl fail-closed ordering + native-endian keys + `Manager.mu` held throughout
- **Dedup tag**: **INCREMENT (codex-171-12)**
- **Evidence**: `pkg/dataplane/userspace/maps_sync.go` L343-826 = **483 LOC** (catalog said ~451; grew). Entire body runs under `Manager.mu` (all sub-calls are `*Locked`). Ordered phases:
  ```
  343  preserve cpumap flag if populated
  ~    stale BPF session flush on FIRST ctrl enable only (HA-safe generation guard)
  ~    stale BPF conntrack flush (TC-egress poisoning guard)
  ~    compute active runtime mode from ctrl+liveness
  ~    set strict flag in ctrl (fail-closed both modes)   <-- FAIL-CLOSED ORDERING
  ~    syncIngressIfaceMapLocked / syncLocalAddressMapsLocked / syncInterfaceNATAddressMapsLocked
  ~    verifyBindingsMapLocked / maybeAutoRebindBusyBindingsLocked
  782  syncBPFCountersLocked(status)                       <-- counter bridge (defined in manager_ha.go)
  ```
- **Proposed decomposition** (matches codex-171-12, refined): `maps_sync_ctrl.go` (cpumap preserve + ctrl mode/strict fail-closed — **keep as one unit**), `maps_sync_flush.go` (stale session/conntrack flush + first-enable guard), `maps_sync_addrmaps.go` (ingress/local/NAT-addr sync — already discrete helpers L883-1199), `maps_sync_bindings.go` (verify/rebind L1199-1400), leaving `applyHelperStatusLocked` as a ~60-LOC orchestrator.
- **Hot-path preservation**: control path (1/s poll), latency/ordering-sensitive. Invariants: **(a) fail-closed ctrl write must stay ordered before map-enable** — do not let the extraction reorder `failClosedUserspaceCtrlLocked`/`blindFailClosedUserspaceCtrlLocked` after classifier sync; **(b) native-endian keys** — `buildUserspaceIngressIfindexes`, `pickInterfaceSnapshotV4/V6`, local-addr `[16]byte` keys use `binary.NativeEndian`/`net.IP` byte order, must move as a unit; **(c) no wider `Manager.mu` hold** and **(d) no new control-socket call** — the split is map-write only, adds no `Status()` calls.
- **Tests + gate**: `maps_sync_cap_test.go` (684), `maps_decouple_test.go` (1,525), `cold_path_status_test.go`, `control_socket_deadline_4036_test.go`; `make test-go` + manager_test suite. Cluster smoke (`make cluster-deploy` + failover) because ctrl-gate governs standby forwarding-armed.
- **Why it matters**: the single most ordering-sensitive control function in the manager; 483 LOC obscures the fail-closed contract.
- **Fix direction**: extract phases as `*Locked` helpers; keep ctrl-write+mode as one indivisible block.
- **Labels**: refactor, class-B, fail-closed, native-endian, control-socket
- **Dedup note**: cataloged; this increments with exact boundaries + the L782 counter-bridge coupling to manager_ha.go.

#### [A7-go-dpmgr] F-A7-3 — manager_ha.go fuses THREE responsibilities (HA state · counter bridge · session sync)

- **Severity**: MEDIUM
- **Confidence**: HIGH
- **Refactor class**: **B (requires guardrails)** — native-endian session keys + control-socket session installs
- **Dedup tag**: **NEW** (the file itself is uncataloged beyond the opus-172 H-4 dead-counter note)
- **Evidence**: `pkg/dataplane/userspace/manager_ha.go` (1,425 LOC) partitions cleanly into three domains that do not share state beyond `Manager`:
  ```
  (a) HA RG state + watchdog    L22-711  syncHAStateLocked, seedHAGroupInventoryLocked,
                                          UpdateRGActive, UpdateHAWatchdog, takeoverReadyLocked,
                                          desiredForwardingArmedLocked, mergeHAStateFromMaps
  (b) counter/flow-stat bridge  L711-848  userspaceCounterSnapshot, sumBindingCounters,
                                          syncBPFCountersLocked, safeDelta  <-- pure OBSERVABILITY, not HA
  (c) session sync + endian     L849-1462 SetSession{V4,V6}, SetClusterSyncedSession*, DeleteSession*,
                                          buildSessionSyncRequest{V4,V6}, nativeUint32ToIP,
                                          networkUint16ToHost, resolveOwnerRGFromZone
  ```
  Block (b) has nothing to do with HA — it aggregates per-binding counters and pushes deltas into the BPF global-counter map (called from `applyHelperStatusLocked`, F-A7-2). It sits in manager_ha.go only by accretion.
- **Proposed decomposition**: `manager_counters.go` (move block (b) — `sumBindingCounters`/`syncBPFCountersLocked`/`safeDelta`/`userspaceCounterSnapshot`); leave HA state + session-sync in manager_ha.go (or further split `manager_session_sync.go` for block (c)).
- **Hot-path preservation**: (b) runs 1/s on the status poll — the delta math and `IncrementGlobalCounter` loop must stay intact (skip-zero-delta guard preserved). (c) builds `SessionSyncRequest` from **native-endian `__be32` keys** (`nativeUint32ToIP` uses `binary.NativeEndian.PutUint32`; `networkUint16ToHost`); these endian helpers must move **with** the session-sync block, not split away. Session installs share the control socket — no new callers.
- **Tests + gate**: manager_test.go Session/Sum/Safe/Merge/Takeover clusters; `make test-go` + `make test-failover` (session-sync + RG state are failover-critical).
- **Why it matters**: the counter-bridge is observability, not HA; keeping it here makes both concerns harder to reason about and hides the `applyHelperStatusLocked`→manager_ha.go cross-file coupling.
- **Fix direction**: peel block (b) to `manager_counters.go`; optionally block (c) to `manager_session_sync.go` carrying the endian helpers.
- **Labels**: refactor, class-B, native-endian, observability, HA
- **Dedup note**: extends opus-172 H-4 (which only named dead counter indices) to a whole-file cohesion finding.

#### [A7-go-dpmgr] F-A7-5 — `compileNAT` 727-LOC + `compilePolicies` 296-LOC fresh compiler god-functions

- **Severity**: MEDIUM
- **Confidence**: HIGH
- **Refactor class**: **A (mechanical)** — pure compile-time, phase boundaries already comment-delimited
- **Dedup tag**: **NEW** (fresh; distinct from cataloged `pkg/config/compiler_nat.go`)
- **Evidence**: `pkg/dataplane/compiler_nat.go` `compileNAT` L159-886 = **727 LOC**; comment phases: source-NAT pool alloc + per-zone-pair v4/v6 rule indices + pool-cache, destination NAT, "record highest pool ID for compileNAT64", stale-delete + zero-unused-pool. `pkg/dataplane/compiler.go` `compilePolicies` L744-1040 = **296 LOC**. Both distinct from the `pkg/config` compiler tree (this is the retained-shim actuation compiler).
- **Proposed decomposition**: `compile_nat_source.go` / `compile_nat_dest.go` / `compile_nat_stale.go` (thin `compileNAT` orchestrator); `compilePolicies` split policy-rule build vs stale-delete.
- **Hot-path preservation**: compile-time only. Guardrail: NAT **counter-ID stability** (`natCounterIDForKey`/`assignNATCounterID`, L84-159) must remain deterministic across the split — `compiler_nat_counter_stability_test.go` (122) is the gate. The "record highest pool ID so compileNAT64 can auto-assign" cross-phase dependency must be preserved (source→64 ordering).
- **Tests + gate**: `compiler_test.go`, `persistent_nat_test.go`, `nptv6_test.go`, `compiler_nat_counter_stability_test.go`; `make test-go`.
- **Why it matters**: two more fresh compiler god-functions in the same package as F-A7-1; the package `dataplane` compiler is systematically under-decomposed.
- **Fix direction**: mechanical phase extraction; preserve counter-ID determinism + source→NAT64 pool-ID ordering.
- **Labels**: refactor, class-A, dataplane-compiler, nat
- **Dedup note**: NEW — the cataloged compiler_nat split is `pkg/config`, not `pkg/dataplane`.

#### [A7-go-dpmgr] F-A7-9 — `FormatStatusSummary` 610-LOC formatter god-function (fresh, A-class)

- **Severity**: LOW
- **Confidence**: HIGH
- **Refactor class**: **A (mechanical)**
- **Dedup tag**: **NEW** (format/status.go not cataloged)
- **Evidence**: `pkg/dataplane/userspace/format/status.go` `FormatStatusSummary` L103-713 = **610 LOC** single fn (next fn `FormatFairnessRSS` at 713). Assembles many independent sections into one string: base active/role, SYN-cookie rows, generated-reply/reject drop counters (#2238/#3615/#3657/#3661 splits), reject-success + budget/rate-limit suppression, degraded-MTU (#2471), worker-runtime table (#869). Pure `strings.Builder` — no invariants, no hot path.
- **Proposed decomposition**: section helpers `formatRejectCounters`, `formatSynCookieSection`, `formatDegradedState`, `formatWorkerRuntimeTable`, each returning a string, called by a thin `FormatStatusSummary`.
- **Hot-path preservation**: none (CLI/REST rendering).
- **Tests + gate**: `format/status_test.go` (831); `make test-go`.
- **Why it matters**: a 610-LOC pure-formatting function is a low-risk, high-readability win; the file is otherwise clean formatting utilities.
- **Fix direction**: mechanical extraction of section builders.
- **Labels**: refactor, class-A, formatting
- **Dedup note**: NEW.

#### [A7-go-dpmgr] F-A7-10 — manager_test.go (6,782 LOC / 164 tests) concrete split plan mapping test clusters to production files

- **Severity**: LOW (review-cost)
- **Confidence**: HIGH
- **Refactor class**: **A (mechanical)** — test-only, split next to production seams
- **Dedup tag**: **NEW** (codex-171-29 catalogs Rust test files only; this Go file is uncataloged)
- **Evidence**: `pkg/dataplane/userspace/manager_test.go` 6,782 LOC, 164 `func Test*`. Topic histogram: **68 `Build*`** (snapshot/address/binding builders), 16 `Derive*`, 9 `Userspace*`, 6 `Session*`/`Update*`, 5 `Clear*`, 4 `Takeover*`/`Snapshot*`/`Read*`/`Desired*`, plus `Sum/Safe/Merge/RGTransition/Sync`.
- **Proposed decomposition** (map clusters to the production file they cover):
  - `maps_sync_build_test.go` ← the 68 `Build*` (buildLocalAddressEntries/buildUserspaceIngress*/buildDesired*) — covers maps_sync.go
  - `manager_ha_test.go` ← Session*/Takeover*/Desired*/Merge/Sum/Safe/RGTransition/Update* — covers manager_ha.go
  - `snapshot_derive_test.go` ← Derive*/Snapshot* — covers the per-domain build*Snapshot (F-A7-8)
  - keep misc lifecycle in manager_test.go (now ~1k LOC)
- **Hot-path preservation**: n/a (tests).
- **Tests + gate**: itself; `make test-go`.
- **Why it matters**: 6,782-LOC test file is the single largest review-cost item in the group; splitting along production seams makes the seam of F-A7-2/F-A7-3 splits verifiable in isolation.
- **Labels**: test-split, class-A
- **Dedup note**: NEW (Go-side test monolith).

#### [A8-go-daemon-ha] F1 — `daemon_run.go::Run` 1,692-LOC startup+shutdown god-function

- **Title:** `Run` fuses all daemon construction, background-loop spawning, and the
  entire shutdown teardown into one 1,692-LOC function.
- **Severity:** High (reviewability/maintainability; the daemon's single most
  behavior-dense function).
- **Confidence:** High.
- **Refactor class:** (B) REQUIRES GUARDRAILS — startup ORDER and shutdown ORDER
  are behavior; wg/goroutine lifecycles and `applyCancelContext` wiring are subtle.
- **Dedup tag:** NEW (uncataloged; daemon.go STRUCT was #4407-fixed to 756, but
  `Run` itself was never in scope — daemon_run.go only ever appeared as a [WATCH]
  heatmap line at 1,932, now 2,329).
- **Evidence:** `func (d *Daemon) Run` L175–1866. Inside: subsystem construction
  `d.routing/frr/ipsec/ra/networkd/dhcpServer/ddns/rpm/ipmon/dhcp/cluster/vrrpMgr/
  dp/gc/eventReader/feeds/lldpMgr/dhcpRelay/snmp/grpcSrv` (~25 assignments,
  L272–1367); ~13 `go`/`go func()` spawns (L400 watchClusterEvents, L957
  watchVRRPEvents, L962 reconcileRGStateLoop, plus 10 wg-tracked loops); boot-class
  gating (`bootstrapMode`, L516 "dataplane arm … suppressed"); forwarding enable;
  then `<-ctx.Done()` (L1687/1692) and a 170-line shutdown teardown
  (L1697–1866: `d.applyCancel()`, boot-timer stop, `rg_active`/`ha_watchdog`
  clear via `runHAShutdownUpdate` with a 2s deadline, RA withdraw, `logFinalStats`
  → `dp.Telemetry`, hitless-vs-teardown branch). Sole caller: `cmd/xpfd/main.go:331`.
- **Proposed decomposition:** Introduce a `bootPlan`/`startupContext` value carried
  through explicit phase methods on `*Daemon`:
  `constructManagers(cfg) → classifyBootAndLifeline() → armDataplaneAndForwarding()
  → startBackgroundLoops(ctx, &wg) → blockUntilShutdown(ctx) → runShutdown(mode)`.
  The shutdown block (L1697–1866) is the cleanest first cut — it is already a
  self-contained sequenced teardown and can move to `runShutdown(ctx, hitless bool)`
  with the `wg`, the RG list, and `d.applyCancel` passed in. `inferIPv6StaticNextHopInterfaces`
  (272-LOC pure helper, L2043) is an independent mechanical extract to
  `daemon_run_routing.go` (Class A).
- **Hot-path preservation analysis:** Not per-packet, but ORDER-critical.
  Preserve: (1) `d.applyCancelContext` is a child of the SIGTERM/SIGINT signal
  context created *after* `signal.NotifyContext` (README: returning `d.daemonCtx`
  makes C1/C2/C3 dead code) — a phase split must keep this creation ordered before
  loop spawns and cancelled at the very start of `runShutdown`; (2) shutdown
  clears `rg_active` BEFORE `dp.Teardown` while the dataplane runtime is still
  live (HA fail-closed); (3) FRR reload/stop stays direct with 15s ctx
  (TimeoutStopSec=20 safety net); (4) the wg-tracked loops must all be joined by
  the same `wg.Wait()` the current tail owns. No new goroutine may be inserted
  between construct and arm.
- **Tests + gate:** `make test-go` (pkg/daemon build/unit); behavioral gates
  `make test-failover` + `make test-ha-crash` (shutdown `rg_active` clear + hitless
  path); `make test-deploy` boot smoke. No existing single-function test — add
  phase-boundary tests as the split lands.
- **Why it matters:** This is the highest-density fusion in the group. Every new
  subsystem or shutdown step grows it; a reviewer cannot hold construct-order +
  teardown-order in one pass, and the C1/C2/C3 cancel wiring depends on statements
  1,500 lines apart staying correctly ordered.
- **Fix direction:** Land `runShutdown` extraction first (lowest risk, self-
  contained), then `inferIPv6StaticNextHopInterfaces`, then the construct/arm/loop
  phases as separate reviewable PRs following the #4407 increment discipline
  (pure code motion, compiler-enforced completeness).
- **Labels:** refactor, pkg/daemon, monolith, god-function.
- **Dedup note:** Not previously filed. daemon.go god-STRUCT (#4407) is a sibling
  concern, not this. Recommend a new tracking issue or a #4407 sub-item.

#### [A8-go-daemon-ha] F2 — `daemon_apply.go::applyConfigLocked` — STATUS-UPDATE + concrete ApplyContext seam

- **Title:** `applyConfigLocked` is now 919 LOC (down from the 1,148 at #4407 filing)
  and its three #2926 ctx-boundaries already partition it into named phases.
- **Severity:** Medium (still >8× the god-fn threshold).
- **Confidence:** High.
- **Refactor class:** (B) REQUIRES GUARDRAILS — apply ORDER is the contract;
  rollback-leak / error-join order is behavior.
- **Dedup tag:** INCREMENT(#4407).
- **Evidence:** `func (d *Daemon) applyConfigLocked` L546–1464 (919 LOC). The
  README's "#4407 Phase A" already peeled `applyTailReconciles` (273 LOC, steps
  8–21, L1465). The **remaining head** carries three explicit boundaries that map
  1:1 to the proposed `ApplyContext` phases:
  - **Phase ActuateNetwork** — C1 boundary (L623 `ctx.Err()`) → steps 0–1.96:
    VRF reconcile, RI/mgmt VRF bind, DHCP default routes, tunnel + xfrmi + bond +
    IPVLAN-fabric create, RETH-MAC link-cycle pre-check, ip-monitoring + feed
    overlay cache refresh.
  - **Phase DataplaneCommit** — C2 boundary (L940 `ctx.Err()`) → steps 2–2.7:
    runtime `ConfigSink.ApplyConfig` (Rust control-socket push), GC aging wire,
    zone→RG map, managed→unmapped teardown (BEFORE networkd), `networkd.Apply`,
    RETH virtual-MAC program, VIP + stable-LL reconcile, AF_XDP socket rebind,
    proxy-ARP, mgmt-VRF re-bind.
  - **Phase RoutingCommit** — C3 boundary (L1225 `ctx.Err()`) → steps 3–3d:
    FRR reload, next-table / rib-group / PBR `ip rule`.
  - Steps 4–7b (neighbor resolve, RA, IPsec, DHCP server/clients) close the head
    before `applyTailReconciles`.
  Sole callers (4): `applyConfig` (bg, `context.Background()`), `applyAndSyncCommitted`
  (L256), `syncAndApply` (L349), `executeConfirmedRollback` (L497). Two use
  `d.applyCancelCtx()`, two use non-cancellable `Background()`.
- **Proposed decomposition:** `type applyContext struct { ctx; cfg; networkdErr,
  dhcpServerErr, ipsecErr, lo0Err, hostInboundErr error; rethNeedsCycle bool;
  zoneRG map[...] }`. Four methods `actuateNetwork(ac) / commitDataplane(ac) /
  commitRouting(ac) / reconcileServices(ac)` each returning at their own
  `ctx.Err()` check. `applyConfigLocked` becomes ~40 lines of sequencing +
  `errors.Join(ac.networkdErr, ac.dhcpServerErr, ac.ipsecErr, ac.lo0Err,
  ac.hostInboundErr)`.
- **Hot-path preservation analysis:** Not per-packet; the **rollback-leak audit**
  is the load-bearing invariant. (1) The five deferred reconcile errors accumulate
  across the whole body and are joined ONLY at the tail — the join operand order is
  pinned (`#1778/#2987/#4433`, `applyTailReconciles` doc); an ApplyContext must
  preserve exact operand order. (2) `applySem` is held by the caller across the
  whole body; phase methods must run synchronously in the caller goroutine (no new
  goroutine, no lock re-acquire) — the README warns the few async callbacks all
  live in the head. (3) C1/C2/C3 must bail only at boundaries "where a skipped tail
  converges on next boot" — each phase runs to completion once entered; do not add
  a finer-grained ctx check mid-phase. (4) RETH-MAC/VIP/rebind sequence between C2
  and C3 must stay one uninterrupted unit.
- **Tests + gate:** `daemon_apply_runtime_test.go:TestApplyConfigLockedSurfacesLo0Failure`
  (error-join wiring), lo0/host-inbound apply tests, `make test-go`; behavioral
  `make test-failover` (apply during failover), `make test-deploy` ping-0-loss.
- **Why it matters:** The apply pipeline is the commit contract; a rollback that
  leaks a half-applied phase (or reorders the error join) is an operator-visible
  correctness regression, so the split must be provably order-preserving.
- **Fix direction:** Extract `commitRouting` (C3→step 3d) first — smallest,
  cleanly bounded by C3. Then `commitDataplane`, then `actuateNetwork`. Keep each
  as its own #4407 increment PR.
- **Labels:** refactor, pkg/daemon, #4407, god-function.
- **Dedup note:** #4407 STRUCT done (756); this is the still-open FN. New detail vs
  catalog: current LOC 919 (not 1,148) and the C1/C2/C3 boundaries ARE the phase
  seam — no fresh seam design needed, just adopt the existing boundaries.

#### [A8-go-daemon-ha] F3 — `vrrp/instance.go` 2,417-LOC — validate 6-file seam + gate preservation

- **Title:** `instance.go` monolith cleanly decomposes into codex-171-27's
  `instance_{state,run,rx,tx,vip,garp}.go`; the failover-timing gates survive
  because same-package method motion is zero-cost.
- **Severity:** Medium (2,417 LOC, past the 2,000 refactor tier).
- **Confidence:** High (seam validated against full function inventory).
- **Refactor class:** (A/B) — mechanical same-package file motion, but VRRP is
  latency-critical so it carries the failover behavioral gate.
- **Dedup tag:** INCREMENT(codex-171-27).
- **Evidence + seam validation:** 64 funcs group with no cross-cutting:
  - `instance_state.go` — timers/priority: `getState/setState`, `advertInterval`,
    `effectiveAdvertInterval`, `masterDownInterval`, `preemptHoldDuration`,
    `preemptingLiveLowerMaster`, `shouldPreemptObservedMaster`, `heldMasterIsStale`,
    `armPreemptHold/disarmPreemptHold`, `stopAndDrainTimer`, `recordMasterAdvert`,
    `masterAdverFloor`, `getPreempt`, preempt setters.
  - `instance_run.go` — `run` (121), `stepBackup` (139), `handleBackupRx`,
    `handleMasterRx`, `resolveEqualPriorityMaster`, `becomeMaster`, `becomeBackup`,
    `emitEvent`.
  - `instance_rx.go` — `receiver` (91), `receiverIPv6` (112), `receiverAfPacket`,
    `parseAfPacketIPv4/6`, `walkIPv6ExtHeaders`, `acceptArrivalIfindex`,
    `expectedIfindex`, `isTimeoutError`.
  - `instance_tx.go` — `sendAdvert`, `sendPacket`, `sendPacketIPv6` (71).
  - `instance_vip.go` — `addVIPs`, `removeVIPs`, `openSocket`, `resolveLocalIPv4`,
    `resolveIPv6LinkLocal`, `reresolveLocalAddrs`, `getLocalIP*`, `vipAddrSet`,
    `canonAddr`.
  - `instance_garp.go` — `garpDampened`, `garpSendAllowed`, `GatewayProbeTarget`,
    `sendGARP`.
- **Hot-path preservation analysis (the reason this is safe):** ALL 64 are methods
  on the same `*vrrpInstance` in `package vrrp`. **Go resolves same-package method
  calls identically regardless of source file** — the split adds ZERO channel hops,
  ZERO lock acquisitions, ZERO dispatch cost to `becomeMaster`/`sendAdvert`/`sendGARP`
  (the ~60ms/30ms critical path). Specific gate preservation:
  - **GARP epoch/dampener (#2081):** `sendGARP`, `garpSendAllowed`, `garpDampened`
    and the struct fields `garpEpoch/lastGARPEpoch/lastGARPTime` move together into
    `instance_garp.go` — both suppression gates stay co-located; the `force=true`
    (ReconcileVIPs) vs `force=false` (becomeMaster/periodic) contract is a field
    read, unaffected by file boundary.
  - **Sync-hold preempt gate (#2082):** `shouldPreemptObservedMaster` /
    `preemptingLiveLowerMaster` / `lastMasterPriority`/`lastMasterSeen` snapshot math
    is the SSOT shared by the #2082 gate AND the #2850 preempt-hold path — keep this
    cluster in `instance_state.go` (NOT split across state/run) so the "strictly
    greater effective priority" comparison stays one readable unit. `becomeMaster`
    (instance_run.go) calls it directly — no seam crosses the gate logic itself.
  - `recordMasterAdvert` learned-interval clamp (#4548, `masterAdverFloor`) stays
    with the state/timer group it feeds.
- **Tests + gate:** `vrrp_test.go` (2,468) + the many `instance_*_test.go`
  (preempt_gate, preempt_holdtime, master_interval, garp_force) already colocate
  by concern and move alongside their production seam; `make test-go` + `vrrp`
  race tests; **behavioral gate `make test-failover`** (the ~60ms path) is
  mandatory before merge.
- **Why it matters:** VRRP is the failover engine; a monolith hides the gate
  interactions (#2081/#2082/#2850/#4548/#4376) that repeatedly bite, and the file
  is already past the "split before adding logic" threshold.
- **Fix direction:** Land `instance_garp.go` and `instance_rx.go` first (most
  self-contained, no timer entanglement), then tx/vip, then the state/run pair
  last (they share the preempt snapshot math — split carefully).
- **Labels:** refactor, pkg/vrrp, codex-171-27, monolith.
- **Dedup note:** Adds to catalog: full function-to-file mapping validated, and the
  same-package-zero-cost argument that answers the brief's "no channel hops / no
  lock acquisitions in becomeMaster/sendAdvert" preservation requirement.

#### [A8-go-daemon-ha] F5 — `daemon_ha_sync.go::startClusterComms` 466-LOC HA-wiring god-function

- **Title:** `startClusterComms` fuses all cluster-comms startup + hook wiring into
  one 466-LOC function.
- **Severity:** Medium.
- **Confidence:** High.
- **Refactor class:** (B) — wiring ORDER and hook-registration completeness are
  behavior; goroutine lifecycles (`commsCtx`) matter.
- **Dedup tag:** NEW.
- **Evidence:** L398–864. Creates independently-cancellable `commsCtx`; resolves
  mgmt-VRF device; starts BPF watchdog heartbeat goroutine; starts heartbeat with
  retry; starts session/config sync with retry; resolves dual-fabric (fab1); starts
  gRPC fabric listener(s); wires ~12 cluster hooks (`SetConfigSyncCallback`,
  `SetPeerConnectedCallback`, `SetBulkSyncOverride`, `SetPeerFailoverFunc` +Commit
  +Batch +CommitBatch, `SetPreManualFailoverHook`, `SetLocalTransferCommitReadyHook`,
  `SetTransferReadinessFunc`, `SetHeartbeatRestartNotifyFunc`, `SetPeerFenceFunc`);
  starts the sweep + eventStreamFallbackLoop.
- **Proposed decomposition:** `startClusterComms` → sequencing shell calling
  `resolveCommsVRF() → startWatchdogHeartbeat(commsCtx) → startHeartbeat(commsCtx)
  → startSessionSync(commsCtx) → wireClusterHooks() → startFabricListeners(commsCtx)`.
  The ~12-line `wireClusterHooks` block (L305–324) is a pure, side-effect-only
  hook-registration extract (Class A).
- **Hot-path preservation analysis:** Not per-packet. Preserve: (1) hook wiring
  must complete BEFORE the heartbeat/sync loops can fire a callback into a nil hook
  — extraction must keep `wireClusterHooks` ordered before the goroutines that
  invoke them; (2) `commsCtx` (independently cancellable sub-context) is the
  restart unit — all spawned loops must observe the SAME commsCtx so a comms
  restart cancels them together; (3) RG0-only config-push gating must stay in the
  callback closures.
- **Tests + gate:** `make test-go` (daemon); behavioral `make test-failover` +
  `make test-ha-crash` (comms restart, fencing, transfer-commit).
- **Why it matters:** This is the single point where every HA hook is bound; a
  missing/mis-ordered wire is a silent failover defect (dual-resign, no fence).
- **Fix direction:** Extract `wireClusterHooks` first (inert), then the per-service
  start helpers.
- **Labels:** refactor, pkg/daemon, HA, god-function.
- **Dedup note:** Not previously filed. The daemon HA surface (4 files) is otherwise
  DOMAIN-cohesive (events/reconcile, userspace-delta, sync-wiring, fabric-fwd) — the
  problem is the god-functions WITHIN (this + reconcileRGState), not the file count.

#### [A8-go-daemon-ha] F6 — `conntrack/gc.go::sweep` 283-LOC with v4/v6 duplication (HA-callback-ordered)

- **Title:** `sweep` is a 283-LOC function with near-duplicate v4/v6 halves and
  ordering-critical HA delete callbacks under `gc.mu`.
- **Severity:** Medium.
- **Confidence:** High.
- **Refactor class:** (B) — HA delete-sync callback ordering + `gc.mu` snapshot
  discipline are behavior (race-tested).
- **Dedup tag:** NEW.
- **Evidence:** `func (gc *GC) sweep` L226–508. Structure: SkipSweep gate →
  `gc.mu.RLock()` snapshot of aging/limit config → empty-table fast path → v4
  iterate (expire on primary only, per-IP count) → v4 `OnDeleteV4` callbacks →
  scratch reuse → v6 iterate → v6 `OnDeleteV6` callbacks → persistent-NAT GC →
  push counts to BPF maps → watermark hysteresis under `gc.mu.Lock()`. The v4 and
  v6 blocks are structurally identical modulo type.
- **Proposed decomposition:** Extract `sweepFamily[V4/V6](snap agingSnapshot,
  isPrimary bool) familyResult` (or a generic over key type) to collapse the
  duplicate halves, plus `applyWatermarkHysteresis(active, deleted)`. `sweep`
  becomes ~60 lines: snapshot → sweepFamilyV4 → sweepFamilyV6 → persistent GC →
  push → hysteresis.
- **Hot-path preservation analysis:** `sweep` runs on the GC goroutine, off the
  forwarding path, but: (1) aging/limit fields (`agingActive`, `earlyAgeout`,
  `high/lowWatermark`, `sessionLimitEnabled`) MUST be snapshotted once under
  `gc.mu.RLock()` at the top and operated on as locals — lock-free access is the
  #3604 data race (`go test -race ./pkg/conntrack`); an extracted helper must
  receive the snapshot, not re-read the fields. (2) `OnDeleteV4/V6` callbacks fire
  INSIDE the loop and feed HA session-sync — keep them non-blocking, at `slog.Debug`
  (the 15 req/s flood rule), and firing in the same iteration order. (3) Expiry is
  skipped on secondary (`IsLocalPrimary`) — the primary/secondary branch must be
  preserved in the extracted family helper. (4) Deletes go through
  `SessionStore.DeleteBatchKnown*` with the iteration `(key,value)` snapshot — do
  not reintroduce a second `GetSession*` read.
- **Tests + gate:** `gc_test.go` (864) + `legacy_dataplane_canary_test.go`;
  `go test -race ./pkg/conntrack/`; `make test-go`. HA path exercised by
  `make test-failover` (delete-sync).
- **Why it matters:** The v4/v6 duplication is a two-place-formula drift risk
  (engineering-style principle #3), and the `gc.mu` snapshot + callback ordering is
  exactly the class that has already produced a race (#3604).
- **Fix direction:** Extract the family helper taking an explicit snapshot struct;
  keep the callback + batch-delete contract byte-identical.
- **Labels:** refactor, pkg/conntrack, GC, HA.
- **Dedup note:** Not previously filed. Reinforces the README's `gc.mu` gotcha.

#### [A8-go-daemon-ha] F7 — `daemon_nft.go::nftRulesFromTerm` 311-LOC term→nft lowering

- **Title:** `nftRulesFromTerm` is a 311-LOC per-term lowering that mirrors the Rust
  filter compiler across ~8 modifier/match dimensions.
- **Severity:** Medium.
- **Confidence:** High.
- **Refactor class:** (B) — each lowering arm has a documented userspace-parity
  contract (#3427/#3433/#3436/#3445/#3483/#3724) that must not drift.
- **Dedup tag:** NEW.
- **Evidence:** `func nftRulesFromTerm(term, family, prefixLists)` L1000–1311.
  Handles: terminating-verdict mapping (accept/discard/reject/PBR/unknown-fail-closed),
  address/prefix-list scope (via `ResolveFilterPrefixListAddrs`), protocol/DSCP
  numeric resolution, icmp type/code independent predicates, log/count/reject
  modifier emission. File total 1,432 LOC, otherwise cohesive nft-table generation.
- **Proposed decomposition:** `nftRulesFromTerm` → `nftTermMatchPredicates(term,
  family)` (addr/proto/dscp/icmp) + `nftTermVerdict(term)` (terminating action) +
  `nftTermModifiers(term)` (log/count/reject). Each maps to a distinct parity test
  already present.
- **Hot-path preservation analysis:** Commit/apply path, not per-packet. Preserve
  the userspace-parity contracts: verdict switch must stay byte-mirror of the Rust
  `filter/compiler.rs` (unknown→drop fail-closed, #3724 M08); address semantics
  positive-wins/empty-except (#3433); numeric proto/dscp (#3436); independent
  icmp-type/code gating (#3483). A split must keep each arm's golden test.
- **Tests + gate:** `daemon_nft` term tests (`TestNftRuleFromTerm*` — ~15 golden
  tests already exist), `TestLo0FilterPayload*`, `host_inbound_nft_test.go`;
  `make test-go`.
- **Why it matters:** This is PRIMARY host-bound enforcement; a lowering drift is a
  fail-open/over-drop control-plane bug (the exact #3427 fall-through-shadow class).
- **Fix direction:** Extract the three sub-lowerings; the golden tests pin each.
- **Labels:** refactor, pkg/daemon, nftables, filter-parity.
- **Dedup note:** Not previously filed for size (the file's correctness history is
  heavily documented in the README, but the 311-LOC fn itself is uncataloged).

#### [A9-go-api-cli] F1 — `newCollector` is a 1,886-LOC single-function descriptor wall

- **Severity:** Low (maintainability) · **Confidence:** High
- **Refactor class:** (A) MECHANICAL/SAFE
- **Dedup tag:** INCREMENT(codex-171-15)
- **Evidence:** `pkg/api/metrics_descriptors.go` is 1,896 LOC and contains exactly ONE
  function — `grep -n '^func '` returns only `10:func newCollector(srv *Server) *xpfCollector {`.
  The body runs to EOF (1,896), i.e. ~1,886 LOC building `prometheus.NewDesc(...)` for
  every metric family, assembled into one `&xpfCollector{...}` literal returned at the end.
- **Proposed decomposition:** split into per-domain descriptor constructors returning
  partial structs or appending into a shared builder:
  `metrics_descriptors_{sessions,nat,cos,fairness,worker,neighbor,wireguard,eventstream,fabric}.go`,
  each `func (…) descFooBar() fooDescs`, with `newCollector` reduced to a ~40-line
  aggregator calling them. Matches the file-per-domain shape metrics_userspace.go already has.
- **Hot-path preservation:** none — `newCollector` runs ONCE at server construction. No
  scrape-path or per-packet code. Zero perf risk.
- **Tests + gate:** `pkg/api/metrics_descriptor_coverage_test.go` (726) +
  `metrics_test.go` (2,432) already assert descriptor presence/coverage; they move with the
  descriptors or stay as-is (they reference the collector, not file layout). Gate: `make test-go`.
- **Why it matters:** any new metric edits a 1.9k-LOC function; review diffs are unanchored,
  merge conflicts are guaranteed on a busy metrics surface.
- **Fix direction:** mechanical carve; no behavior change; land alongside the metrics_userspace
  file-carve (F2) as one "metrics_*.go domain split" PR.
- **Labels:** monolith, god-function, presentation-plane
- **Dedup note:** cataloged codex-171-15 at 1,867 LOC; re-measured at HEAD = 1,896 file / 1,886 fn.

#### [A9-go-api-cli] F3 — Session view/filter/projection is re-implemented THREE times (REST + gRPC + CLI), with confirmed behavioral drift

- **Severity:** Medium · **Confidence:** High
- **Refactor class:** (B) REQUIRES GUARDRAILS
- **Dedup tag:** INCREMENT(codex-171-25) — adds concrete signatures + a live drift instance
- **Evidence:** the same session enrichment/filter/pagination logic exists in three packages:
  - REST `pkg/api/sessions.go`: `sessionEntryV4`(1056)/`sessionEntryV6`(1110),
    `sessionQuery.matchV4`(946)/`matchV6`(990), `sessionIfaceMatches`(1037),
    `resolveSessionEgressIface`(1047), `encodePageTokenV4/V6`, `decodeSessionKeyV4/V6`,
    `parseSessionPrefix`, `protoFilterMatches`, `sessionStateName`.
  - gRPC `pkg/grpcapi/server_sessions.go`: `sessionEntryV4`(1186)/`sessionEntryV6`(1242),
    `sessionFilter.matchV4`(449)/`matchV6`(494), `sessionIfaceMatches`(1300),
    `resolveSessionEgressIface`(1309), `encodePageTokenV4/V6`, `decodeSessionKeyV4/V6`,
    `parseSessionPrefix`, `protoFilterMatches`, `sessionStateName` — **same names, same bodies**.
  - CLI `pkg/cli/session_filter.go`: `sessionFilter` type + `matchesV4`(200)/`matchesV6`(245),
    `ifaceMatches`(336), `resolveEgressIface`(345), `hasFilter`, `validate`; plus the render
    logic inlined in `cli_show_flow.go::showFlowSession` (F7).

  The bodies are near-line-for-line identical. `sessionEntryV4` differs only in output type
  (`SessionEntry` REST struct vs `*pb.SessionEntry` vs CLI tab row) and field spelling
  (`PolicyID` vs `PolicyId`, `Age` vs `AgeSeconds`); the NAT-string formatting
  (`fmt.Sprintf("SNAT %s:%d"...)` / `"SNAT [%s]:%d"` for v6) is byte-identical across copies.
  **Live drift already present at HEAD** — egress-interface resolution diverges:
  - REST (`sessions.go:1061`): `resolveSessionEgressIface(FibIfindex, FibVlanID, EgressZone,…)`
    which only consults `egressIfaces` **when `fibIfindex != 0`**, else `zoneIfaces[egressZone]`.
  - gRPC (`server_sessions.go:1191`): inlines `egressIfaces[{FibIfindex,FibVlanID}]`
    **unconditionally** (even when FibIfindex==0) before falling back.
    → for a session with `FibIfindex==0` but a stale `{0,vlan}` egress-map entry, gRPC and REST
    can name different egress interfaces. The in-code comment at `sessions.go:1172-1178` already
    documents that `protoFilterMatches` "mirrors the gRPC … and CLI … contract" and that a prior
    drift (case-sensitive REST compare) silently returned empty results (#2935) — proof this
    seam bites in production.
- **Proposed decomposition:** new package `pkg/sessionview` exposing surface-neutral primitives:
  ```go
  type Entry struct { /* neutral fields: SrcAddr,DstAddr,Ports,Proto,Zones,NAT,Age,Idle,... */ }
  type Filter struct { /* src/dst prefix, ports, proto, zone, iface, state */ }
  func (Filter) MatchV4(k dataplane.SessionKey,  v dataplane.SessionValue)  bool
  func (Filter) MatchV6(k dataplane.SessionKeyV6, v dataplane.SessionValueV6) bool
  func BuildV4(k dataplane.SessionKey,  v dataplane.SessionValue,  now uint64, view View) Entry
  func BuildV6(k dataplane.SessionKeyV6, v dataplane.SessionValueV6, now uint64, view View) Entry
  func ResolveEgressIface(fibIfindex uint32, fibVlanID uint16, egressZone uint16, view View) string
  func EncodePageTokenV4/V6(...) string;  func DecodePageToken(tok string) (kind string, key []byte, error)
  func ProtoFilterMatches(p uint8, filter string) bool;  func StateName(uint8) string
  ```
  Each surface keeps its own thin adapter (`Entry`→`SessionEntry`, `Entry`→`*pb.SessionEntry`,
  `Entry`→tabwriter row). REST/gRPC/CLI call the shared primitives.
- **Hot-path preservation:** N/A — control-plane query path, not per-packet. `MatchV*`/`BuildV*`
  run per session row on an operator show; allocation profile unchanged (still one `Entry`/row).
  No new locks. The one thing to preserve: pagination page-token encode/decode must stay a single
  codec so REST cursor and gRPC cursor tokens remain interchangeable (they share the fabric proxy).
- **Tests + gate:** `pkg/api/sessions_parity_test.go`(221) + `sessions_pagination_test.go`(452) +
  `sessions_ha_scope_3423_test.go`(425) + `pkg/grpcapi/*sessions*_test.go` + `pkg/cli/session_*_test.go`.
  Add a golden cross-surface parity test asserting REST/gRPC/CLI produce identical Entry fields for
  a fixed session-table fixture (would have caught the egress drift). Gate: `make test-go`.
- **Why it matters:** three copies of security-relevant projection (NAT disclosure, zone naming,
  filter matching) drift silently; #2935 already shipped one such drift to users. A shared package
  makes divergence a compile/test event.
- **Fix direction:** extract `pkg/sessionview`; migrate gRPC first (widest field set), then REST
  adapter, then CLI; delete the duplicated fns. Reconcile the egress-resolution divergence to ONE
  rule as part of the extraction (decide gRPC-unconditional vs REST-guarded; the guarded form
  is safer).
- **Labels:** dedup, cross-surface, correctness-drift, presentation-plane
- **Dedup note:** cataloged codex-171-25 (no signatures given); this INCREMENT supplies the
  package API and the specific live drift (egress resolution) + the #2935 precedent.

#### [A9-go-api-cli] F4 — REST `showTextHandler` re-renders 12 topics that gRPC `ShowText` already renders

- **Severity:** Medium · **Confidence:** High · **Refactor class:** (B) REQUIRES GUARDRAILS
- **Dedup tag:** INCREMENT(codex-171-24)
- **Evidence:** `pkg/api/show_text.go::showTextHandler` (312 LOC) contains a `switch topic` that
  independently renders `schedulers, snmp, dhcp-relay, firewall, alg, dynamic-address,
  address-book, applications, flow-monitoring, flow-timeouts, nat-static, nat-nptv6` straight from
  `cfg`. Every one of those topics is ALSO rendered by the gRPC path
  (`pkg/grpcapi/server_show.go::ShowText` → `server_show_security_text.go` `showSchedulers`,
  `showApplications`, `showAlg`, `showDynamicAddress`, `showAddressBook`, … +
  `server_show_dhcp_lldp_snmp.go` `showSNMP`, `showDHCPRelay`). Two independent formatters for the
  same operator output — e.g. `flow-timeouts` prints the "#2486 ipsec-vpn not enforced" note in
  the REST copy; the gRPC copy must be kept in lockstep by hand.
- **Proposed decomposition:** the codex-171-24 `pkg/showtext` package: move each topic renderer to
  `func TopicX(buf *strings.Builder, cfg *config.Config)` in `pkg/showtext`; both
  `grpcapi.ShowText` and `api.showTextHandler` call the same functions. REST stops re-implementing.
- **Hot-path preservation:** N/A — config-render path.
- **Tests + gate:** `pkg/grpcapi/server_show_golden_test.go`(290) + REST handler tests; add a
  parity test that REST `?topic=flow-timeouts` == gRPC `ShowText{flow-timeouts}`. Gate: `make test-go`.
- **Why it matters:** the whole point of routing CLI through gRPC ShowText is a single renderer;
  REST silently forked a subset, so operators get different text depending on transport.
- **Fix direction:** extract `pkg/showtext`, delete the REST `switch`, have both surfaces call it.
- **Labels:** dedup, cross-surface, presentation-plane
- **Dedup note:** cataloged codex-171-24; INCREMENT names the exact 12 duplicated topics.

#### [A9-go-api-cli] F5 — `server_diag.go` is a low-cohesion dumping ground; `SystemAction` is a 413-LOC 18-way dispatch

- **Severity:** Low · **Confidence:** High · **Refactor class:** (A) MECHANICAL/SAFE
- **Dedup tag:** NEW
- **Evidence:** `pkg/grpcapi/server_diag.go` (1,602 LOC) mixes three unrelated responsibilities:
  1. **Live diagnostics streaming** — `Ping`/`Traceroute`/`streamDiagCmd`/`MonitorPacketDrop`(214)/
     `MonitorInterface`(166)/`proxyMonitorInterface`;
  2. **Destructive system administration** — `SystemAction`(1176→1589 = 413 LOC, 18 `case "…"`
     covering reboot/halt/power-off/zeroize/clear-config-lock/clear-arp/clear-*-statistics/…),
     `logSystemAction`, `schedulePowerAction`, peer proxying;
  3. **Factory-reset secret erasure** — `zeroizeConfigDir`, `zeroizeRenderedConfigs`,
     `zeroizeLookupUID`, `zeroizeLoginAccounts`, `readProvisionedMarkerUID`, `isTextRollbackFile`.
  These share the file only because they're all "diag/admin RPCs." The zeroize cluster is
  security-load-bearing (#4576 partial-wipe surfacing, #4108 journal-ordering) and deserves its
  own reviewable module.
- **Proposed decomposition:**
  - `server_diag.go` → keep Ping/Traceroute/Monitor* live-diag streams.
  - `server_system_action.go` → `SystemAction` + `logSystemAction`/`schedulePowerAction`/peer proxy;
    within it, split the 18-case switch into a `map[string]func(...)` or small per-action helpers
    (each case is already short, so the switch is a dispatch — carve for reviewability, not depth).
  - `server_zeroize.go` (or `pkg/grpcapi/zeroize`) → the six factory-reset helpers, co-located with
    their #4576/#4108 invariants and their own focused test.
- **Hot-path preservation:** none — all cold RPC handlers. Monitor* stream at operator cadence.
- **Tests + gate:** `pkg/grpcapi/system_action_test.go`(222) + `server_packet_drop_validation_3382_test.go`
  move with their targets; `make test-go`.
- **Why it matters:** a destructive, security-sensitive `zeroize` path is buried in a diag file next
  to `ping`; reviewers scanning "diagnostics" under-attend the wipe logic where #4576/#4108 live.
- **Fix direction:** three-way file carve; no logic change; preserve the journal-before-wipe ordering.
- **Labels:** monolith, low-cohesion, security-adjacent, dumping-ground
- **Dedup note:** NEW — server_diag.go was not in the catalog.

#### [A9-go-api-cli] F6 — `show interfaces` render duplicated gRPC↔CLI, each with 300–360 LOC god-fns

- **Severity:** Low-Medium · **Confidence:** High · **Refactor class:** (B) REQUIRES GUARDRAILS
- **Dedup tag:** INCREMENT(fable-168 §4.2)
- **Evidence:** two parallel copies with matching structure and god-fns:
  - gRPC `pkg/grpcapi/server_show_interfaces.go`: `ShowInterfacesDetail`(69→417 = **348 LOC**),
    `showInterfacesTerse`(417→776 = **359 LOC**), `writeRethMemberSummary`, `writeRethDetail`,
    `rethMemberKernelState`, `baseIfName`.
  - CLI `pkg/cli/cli_show_interfaces.go`: `showInterfaces`(62→473 = **411 LOC**),
    `showInterfacesTerse`(796→1104 = **308 LOC**), `showInterfacesRethMemberSummary`,
    `showInterfacesRethDetail`, `rethMemberLinkState`, `baseIfName` (duplicated helper).
  fable-168 §4.2 already flagged the reth-resolution (`RethToPhysical`/`physToReth`) as
  drift-prone across these two; the whole terse/detail render, not just reth-resolution, is forked.
- **Proposed decomposition:** two moves that compound: (a) split each god-fn into
  `renderTerseRow` / `renderDetailBlock` / `renderRethBlock` / `renderStats` helpers; (b) hoist the
  now-small shared helpers into `pkg/ifaceview` (or fold interface rendering behind gRPC like most
  CLI show commands already do — CLI `show interfaces` still renders locally instead of proxying).
  Minimum: one shared reth-resolution + member-state helper so terse and detail cannot drift.
- **Hot-path preservation:** N/A — operator show path; netlink stat reads are already there.
- **Tests + gate:** `pkg/grpcapi/server_show_interfaces_reth_4328_test.go`,
  `pkg/cli/cli_show_interfaces_reth_4328_test.go` (matched pair — proof of the parallel surfaces);
  `make test-go`. Add a parity golden.
- **Why it matters:** interface terse/detail is one of the most-run operator commands; two 350-LOC
  renderers guarantee eventual divergence in reth/VIP/stat display (the fable-168 concern).
- **Fix direction:** decompose the four god-fns, then dedup reth/member helpers into one package.
- **Labels:** monolith, god-function, dedup, cross-surface
- **Dedup note:** INCREMENT of fable-168 §4.2 (which named only the reth-resolution helper); this
  adds the god-fn measurements and the full terse/detail fork.

#### [A9-go-api-cli] F7 — `cli_show_flow.go::showFlowSession` is a 542-LOC god-fn re-inlining the session view

- **Severity:** Low-Medium · **Confidence:** High · **Refactor class:** (B) REQUIRES GUARDRAILS
- **Dedup tag:** INCREMENT(codex-171-25) — this is the CLI render half of F3
- **Evidence:** `pkg/cli/cli_show_flow.go::showFlowSession` (188→730 = **542 LOC**) rebuilds
  `zoneNames`/`zoneIfaces`/`policyNames` maps, dispatches top-talkers/summary/brief, and inlines
  V4+V6 row rendering with the same NAT-string / zone-name / age-idle logic that F3's
  `sessionEntryV4/V6` implement in REST and gRPC. The projection is copied a third time, here fused
  into one long function instead of being factored.
- **Proposed decomposition:** after F3 lands `pkg/sessionview`, reduce `showFlowSession` to:
  parse filter → fetch (local + peer) → for each row `sessionview.BuildV4/V6` → adapter to
  tabwriter/summary. Split the summary aggregation and top-talkers branches into their own fns
  (they already partially exist: `showTopTalkers`, `newSessionBriefWriter`).
- **Hot-path preservation:** N/A.
- **Tests + gate:** `pkg/cli/session_display_test.go`(178), `session_filter_test.go`(223) + the
  cmd/cli `show_flowsession_3439_test.go`; `make test-go`.
- **Why it matters:** the single largest fn in pkg/cli and the third copy of session projection;
  fixing F3 without touching this leaves the CLI drift vector open.
- **Fix direction:** land F3 first, then gut showFlowSession to an adapter.
- **Labels:** god-function, dedup, cross-surface
- **Dedup note:** INCREMENT(codex-171-25); quantifies the CLI render half.

#### [A10-go-services] F-1 — routing/tunnel.go: `t.mu` held across full netlink+exec reconcile (lock-scope narrowing)

- **Title:** `tunnelManager.Apply` serializes all operator status reads behind the entire netlink+exec tunnel reconcile.
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** **C (performance-positive — lock narrowing)**
- **Dedup tag:** INCREMENT(codex-173-8) — adds the concrete plan/apply boundary + gen-counter preservation the catalog asked for.
- **Evidence:** `Apply` (tunnel.go:277) takes `t.mu.Lock(); defer t.mu.Unlock()` at :278–279 and holds it across (a) pure in-memory diff (desired/wgDesired/oldOwned/next maps, :300–423), (b) the GRE removal loop's `t.ops.LinkByName`/`t.ops.LinkDel` netlink syscalls (:331–357), (c) the WG address-prune loop `pruneAppliedAddrsLocked` (AddrList/AddrDel, :410), and (d) the per-tunnel apply loop calling `applyWireguardTunLocked` (101 LOC), `applyAnchorLocked` (148 LOC), `applyKernelTunnelLocked` (166 LOC) — each of which does LinkAdd/LinkDel/LinkSetUp/AddrReplace and can shell out. The only other `t.mu` sites are `stopAll` (:1437), `GetKeepaliveState` (:1730), `Clear` (:1741), `GetStatus` (:1798). So a `show interfaces`/gRPC tunnel-status read (`GetStatus`, `GetKeepaliveState`) blocks for the full duration of a config-driven tunnel reconcile.
  ```go
  func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
      t.mu.Lock()
      defer t.mu.Unlock()                    // held across ALL of the below
      ...
      if link, err := t.ops.LinkByName(name); err == nil {
          if delErr := t.ops.LinkDel(link); ...   // netlink under lock
      ...
      t.applyKernelTunnelLocked(tc)          // LinkAdd/LinkSet/Addr* + exec under lock
  ```
- **Callers:** `Apply` is the tunnel actuation leg of daemon config apply; `GetStatus`/`GetKeepaliveState` are the CLI/gRPC status readers (`show`), and keepalive goroutines (`keepaliveTick` :1564) run **lock-free** via `gen *atomic.Uint64` — so the invariant "no locks on keepalive ticks" already holds and must be preserved.
- **Proposed decomposition (3 phases, catalog names):**
  1. `BuildTunnelPlan(tunnels) -> tunnelPlan` — under a **short read-lock**, snapshot `ownedNames/appliedAddrs/appliedRI/wgConfigured` and compute the removal set, WG-prune set, and per-tunnel action list into a pure `tunnelPlan` value. No netlink.
  2. `ApplyTunnelPlan(plan) -> tunnelResult` — execute netlink/exec **without holding `t.mu`**, accumulating mutations (added/removed names, new appliedAddrs, prune residuals, keepalive start/stop) into a local `tunnelResult` rather than mutating `t.*` in place.
  3. `CommitTunnelState(plan, result)` — under a **short write-lock**, publish the accumulated maps atomically (`ownedNames`, `wgConfigured`, `appliedAddrs`, `appliedRI`, `tunnels`) so `GetStatus` never observes half-reconciled state.
- **Hot-path preservation analysis (the load-bearing part):**
  - **Generation counter (`linkGen`, #1918/#4076) ordering must survive the split.** `bumpLinkGenLocked` (:255) is currently called *inside* the netlink helpers (e.g. the "Drain the stale runner first; bump the generation" comment at :803, and #4076 recreate bump :584–592) so that a stale keepalive runner still holding the old `gen` value drops its `LinkSet*` on the next lock-free `gen.Load()` (:1618–1622). Because keepalive ticks are **already lock-free** (atomic `gen`, own netlink, no `t.mu`), the real synchronization is the atomic — NOT `t.mu`. The narrowing is therefore sound *iff* the gen bump is published (atomic store, which it is) **before** the corresponding `LinkDel`/`LinkAdd` executes in phase 2. Keep the bump co-located with the netlink op inside `ApplyTunnelPlan`, not deferred to `CommitTunnelState`.
  - **`stopKeepaliveLocked` (:1459) drain-before-recreate** must remain ordered before the LinkDel of the same name; keep it in the phase-2 action for that tunnel.
  - **Retry/ownership retention semantics** (transient `LinkByName` EBUSY → retain name in `next`/`nextWG`, :335/352/406/416) are correctness-critical (#1919 Codex r1/r2 leak chain). These must move into `tunnelResult` accumulation unchanged — a name whose LinkDel failed stays owned.
  - Net effect: status reads (`GetStatus`) contend only on two short critical sections instead of the whole reconcile; no per-packet path touched (tunnel.go is control-plane).
- **Tests that move + gate:** `routing_test.go` (1,805), `tunnel_reconcile_test.go` (1,649), `tunnel_keepalive_test.go` (574), `tunnel_anchor_keepalive_test.go` (350), `iface_reuse_test.go` (650), `tunnel_prober_test.go` (263). Gate: `go test ./pkg/routing/...` must stay green (esp. the `#1918`/`#1919`/`#4076` gen-counter + transient-removal-leak cases), then a tunnel feature end-to-end (GRE/anchor up, keepalive down-action LinkSetDown, status read during an apply).
- **Invariants at risk:** `t.mu` ownership (currently trivially total-order — narrowing must not expose partial `appliedAddrs`), keepalive gen-counter publish-before-recreate ordering, ownership-retention-on-transient-error.
- **Why it matters:** operator `show` latency spikes during multi-tunnel commits; the split is the only performance-relevant seam in this whole module group and the catalog explicitly flagged it C-class.
- **Fix direction:** land the plan/apply/commit split; keep gen bump + `stopKeepaliveLocked` inside phase 2 next to the netlink op; assert `GetStatus` cannot see partial state via a test that reads status mid-apply.
- **Labels:** refactor, class-C, lock-narrowing, hot-path-adjacent.
- **Dedup note:** cataloged as top-WATCH codex-173-8; this entry supplies the concrete boundary + gen-counter preservation requested.

#### [A10-go-services] F-2 — upgrade/cutover.go: `Runner.Run` 431-LOC god-function

- **Title:** `Runner.Run` is a 431-LOC linear cutover orchestrator (preflight→copy→verify→flip→cleanup) in one function.
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** **A (mechanical) / B (guardrails — journal ordering)**
- **Dedup tag:** **NEW** (uncataloged file; cutover.go 953 LOC).
- **Evidence:** `func (r *Runner) Run(opts Options) (err error)` spans cutover.go:135–566 = **431 LOC**. The same file already has the natural phase boundaries as separate helpers — `preflight` (:604, 101), `copyStaged` (:712, 110), `cleanupFailedVerifyCopy` (:892, 61) — but `Run` still inlines the sequencing, journal writes, and error/rollback handling of the whole A/B image cutover.
- **Proposed decomposition:** extract the in-line phases of `Run` into `runPreflight`/`runStage`/`runVerify`/`runFlip`/`runFinalize` returning through a shared `*Journal`; `Run` becomes the phase sequencer + rollback dispatcher. Mirrors the `daemon_apply.go applyConfigLocked` ApplyContext-phases pattern (cataloged #4407).
- **Hot-path preservation analysis:** none — this is a one-shot upgrade orchestration path, not per-packet/per-apply. The only ordering invariant is **Journal write ordering** (each phase must journal before the irreversible step so a crash mid-cutover is recoverable); the extraction must keep each `j.Record(...)` before its side effect. This is Class B for that reason.
- **Tests + gate:** `runner_test.go` (720), `cutover_refuse_test.go` (361), `stagedgen_cut_test.go` (536), `verify_cleanup_test.go` (362). Gate: `go test ./pkg/upgrade/...` + an end-to-end staged cutover dry-run.
- **Why it matters:** 431 LOC crosses the "god function" bar (>150–200 LOC) by 2×; the crash-recovery journal ordering is exactly the kind of load-bearing logic that a 431-LOC function hides.
- **Fix direction:** phase-extract behind a `Journal`; keep journal-before-sideeffect ordering; no behavior change.
- **Labels:** refactor, class-A/B, god-function.
- **Dedup note:** not previously cataloged.

#### [A10-go-services] F-3 — frr/policy_render.go: `renderRouteMapForPolicy` 406-LOC god-function

- **Title:** Single 406-LOC route-map renderer inside the 1,938-LOC policy render monolith.
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** **B (guardrails — FRR render is command-injection-adjacent + sanitize-belt sensitive)**
- **Dedup tag:** INCREMENT(codex-173-18) — the catalog named the file split; this adds the specific god-fn.
- **Evidence:** `func (m *Manager) renderRouteMapForPolicy(...)` at policy_render.go:1532 spans to EOF :1938 = **406 LOC**; `renderRouteFilterEntry` (:1135) is 173 LOC. Together ~30% of the file is two functions.
- **Proposed decomposition:** the cataloged `render_bfd/protocols/routemaps/route_filters/policy_options.go` split; within route-maps, break `renderRouteMapForPolicy` into `renderMatchClauses`/`renderSetClauses`/`renderTermAction` (the term loop) so each match/set family is isolated.
- **Hot-path preservation analysis:** none (control-plane render). **FRR reload semantics + sanitize-belt** are the invariants: prior findings (opus-172 M-4/M-5 cross-context route-map default leak, ps-020 community/as-path newline injection, #4481/#4482 set-clause injection) live in this render path. A split MUST keep every operator-string sanitize call co-located with its emit so a term arm can't drift past the belt.
- **Tests + gate:** the FRR test corpus is already seam-organized — `policy_setclause_injection_4482_test.go`, `policy_routemap_leak_4481_test.go`, `policy_default_action_2998_test.go`, `policy_injection_4097_test.go`, `policy_as_path_prepend_2892_test.go`, `fbf_table_render_test.go`. Gate: `go test ./pkg/frr/...` (all injection/leak pins) + `frr-reload.py` accepts generated frr.conf.
- **Why it matters:** 406 LOC hiding sanitize-belt-critical logic is exactly where an injection regression slips in unnoticed.
- **Fix direction:** file-split per catalog; sub-split the route-map fn keeping sanitize-with-emit.
- **Labels:** refactor, class-B, god-function, security-adjacent.
- **Dedup note:** file cataloged codex-173-18; god-fn detail is new.

#### [A10-go-services] F-4 — dhcprelay/relay.go: `runRelaySession` 343-LOC god-function

- **Title:** `Manager.runRelaySession` fuses socket setup, per-packet relay loop, option-82, and reply delivery in 343 LOC.
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** **B (guardrails — reply-validation + L2 delivery security)**
- **Dedup tag:** INCREMENT(codex-173-20) — catalog named the file split (manager/session/sockets/reply_validate/delivery_l2/option82); this pins the god-fn.
- **Evidence:** `func (m *Manager) runRelaySession(ctx, ...)` at relay.go:846 spans to :1189 = **343 LOC**. Sibling `handleServerResponses` (:1245) 106, `deliverReply` (:1389) 66, `Apply` (:627) 90. The session function is the dominant blob.
- **Proposed decomposition:** exactly the catalog seam — pull socket bind/`relaySpec` reconcile into `sockets.go`, the request→server forward into `session_forward`, the server→client path (already partly `handleServerResponses`/`deliverReply`) fully into `delivery_l2.go` + `reply_validate.go`, option-82 append/strip into `option82.go`.
- **Hot-path preservation analysis:** relay runs a `net.PacketConn` read loop (per-DHCP-packet, but DHCP is low-rate — not a dataplane hot path). Invariants: **source validation** (fable-167 I-4 relay forwards without source validation), **buildL2Reply length truncation** (ps-038 F, DHCP buildL2Reply len), and **giaddr handling** (relay_giaddr_linux). Keep the validation before delivery when splitting.
- **Tests + gate:** `relay_test.go` (2,033), `delivery_test.go` (894), `l2send_test.go` (209), `relay_giaddr_linux_test.go` (124). Gate: `go test ./pkg/dhcprelay/...` + a relayed DHCP DORA end-to-end.
- **Why it matters:** 343 LOC is 2× the god-fn bar; the reply-validation security fixes are buried inside it.
- **Fix direction:** catalog file split; extract the session loop into forward/deliver/validate helpers.
- **Labels:** refactor, class-B, god-function.
- **Dedup note:** file cataloged codex-173-20; god-fn detail new.

#### [A10-go-services] F-5 — ipsec/policy.go: `renderConfig` 272-LOC god-function (prior finding GREW)

- **Title:** swanctl `renderConfig` is a 272-LOC render god-function; the file grew from the prior ~880 to 1,059 LOC.
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** **B (guardrails — strongSwan render fail-open + traffic-selector injection)**
- **Dedup tag:** STATUS-UPDATE (prior-campaign ~880-line finding) + NEW god-fn detail.
- **Evidence:** `func (m *Manager) renderConfig(ipsecCfg *config.IPsecConfig) (string, error)` at policy.go:31 spans to :303 = **272 LOC**; it inlines the skip-belt (unrenderable gateway/IKE-chain backstops), per-VPN ESP proposal building, and swanctl block emission. `PrepareConfig` (:566) 75, `defaultResolveHostFamily` (:745) 60.
- **Proposed decomposition:** `renderConfig` → `renderConnBlock`/`renderChildSA`/`renderESPProposals` + a `renderSkipBelt` guard; keep `PrepareConfig` separate. The file itself splits into `policy_render.go`/`policy_prepare.go`/`policy_resolve.go`.
- **Hot-path preservation analysis:** none (render path). Invariants: **render fail-open** (codex-172 C172-H01 IPsec render/reload fail-open leaves stale tunnels), **traffic-selector sanitization** (fable-163 F4 local_ts/remote_ts unsanitized → root RCE, #4098 trafficselector render), **`protocol ah` rendered as ESP** (fable-167 V-2). Each VPN's skip-belt decision must stay before its emit.
- **Tests + gate:** `ipsec_test.go` (1,850), `swanctl_render_test.go` (810), `trafficselector_render_4098_test.go`, `proposalset_ah_hb167_test.go`, `ike_chain_failclosed_test.go`. Gate: `go test ./pkg/ipsec/...` + `swanctl --load-all` accepts generated conf.
- **Why it matters:** the file crossed 1,000 LOC and its central render fn is the RCE/fail-open surface — modularity here is a security review lever.
- **Fix direction:** extract render sub-blocks; keep skip-belt-before-emit.
- **Labels:** refactor, class-B, god-function, security-adjacent.
- **Dedup note:** prior ~880-line finding; now 1,059 — status is "grew, still open," plus the specific 272-LOC fn.

#### [A10-go-services] F-6 — logging/ringbuf.go: `EventReader` god-struct (8-domain fanout dumping-ground)

- **Title:** `EventReader` fuses event decode, four name-map enrichment tables, and three-way (callback/syslog/local) fanout — 8 independently-locked domains on one struct.
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** **B (guardrails — goroutine-safe swap semantics)**
- **Dedup tag:** **NEW** (uncataloged; ringbuf.go 1,369 LOC).
- **Evidence (ringbuf.go:198–217):**
  ```go
  type EventReader struct {
      source        EventSource
      buffer        *EventBuffer
      syslogMu      sync.RWMutex ; syslogClients []*SyslogClient
      localMu       sync.RWMutex ; localWriters  []*LocalLogWriter
      callbackMu    sync.RWMutex ; callbacks     []EventCallback
      zoneNamesMu   sync.RWMutex ; zoneNames     map[uint16]string
      policyNamesMu sync.RWMutex ; policyNames   map[uint32]string
      ifNamesMu     sync.RWMutex ; ifNames       map[uint32]string
      appNamesMu    sync.RWMutex ; appNames      map[uint16]string
      sessionSeq    uint64
  }
  ```
  Seven RWMutexes guarding seven independent slices/maps + a decode source + a buffer + a sequence counter. The surface (`SetZoneNames`/`SetPolicyNames`/`SetIfNames`/`SetAppNames`/`AddCallback`/`SetSyslogClients`/`SetLocalWriters`/`ReplaceSyslogClients`/`ReplaceLocalWriters`/`ForwardLogMsg`) shows three unrelated concerns bolted together: (1) RT_FLOW decode, (2) ID→name enrichment, (3) sink fanout.
- **Callers:** the daemon flow-exporter reconcile (registers/clears the indirection callback, #2075), syslog stream config, local-log config. `Run` (:403) is the reader loop; `ProcessRawEvent` (:439) the userspace-transport entry.
- **Proposed decomposition:** `ringbuf/decode.go` (rawEvent + `ProcessRawEvent` + `eventTimeFromWire`), `ringbuf/enrich.go` (an `enrichment` sub-struct owning the four name maps + their swaps), `ringbuf/fanout.go` (a `sinkSet` owning callbacks/syslogClients/localWriters + `ForwardLogMsg`/`Replace*`). `EventReader` becomes a thin composition of `source + buffer + enrichment + sinkSet`.
- **Hot-path preservation analysis:** the event reader Run loop is per-event (RT_FLOW rate, not per-packet) but latency-sensitive under log storms. Invariants: **atomic swap-and-close** (`ReplaceLocalWriters`/`ReplaceSyslogClients` swap then close old — a split must keep the close-after-swap so a concurrent `ForwardLogMsg` never writes to a closed sink), and **native-endian port decode** (rawEvent reads ports by explicit offset). No allocation added to the per-event path.
- **Tests + gate:** `binary_test.go` (1,054), `aggregator_test.go`, `syslog_reentrancy_test.go`, `syslog_resilience_test.go`, `session_close_format_test.go`, `per_policy_log_test.go`. Gate: `go test ./pkg/logging/...` (esp. reentrancy/resilience swap tests) + syslog stream reconcile end-to-end (add+remove receiver, confirm no leaked client via `SyslogClientCount`).
- **Why it matters:** a dumping-ground struct with 7 mutexes is the low-cohesion smell the discipline targets; the swap-and-close ordering is a real correctness invariant that's easy to break when the sinks are one flat struct.
- **Fix direction:** compose `enrichment` + `sinkSet` sub-structs; preserve swap-then-close.
- **Labels:** refactor, class-B, god-struct, low-cohesion.
- **Dedup note:** not previously cataloged.

#### [A10-go-services] F-7 — snmp/v3.go: USM crypto + PDU-build fusion in one 1,084-LOC file

- **Title:** SNMPv3 USM key-derivation, auth-HMAC, privacy-crypto, and response-PDU assembly share one file.
- **Severity:** Low→Medium
- **Confidence:** High
- **Refactor class:** **B (guardrails — crypto correctness + timeliness/replay)**
- **Dedup tag:** **NEW** (uncataloged; v3.go 1,084 LOC).
- **Evidence:** v3.go carries `usmUser` key material (:37), `deriveV3Users`/`passwordToKey` (key localization :52–75), `authHashFunc`/`authTruncLen` (HMAC md5/sha/sha256 :76–90), the decrypt/auth-check dispatch (:162 "encrypted PDU MUST be authenticated" drop), and `buildV3Response` (:954, 104 LOC PDU assembly). Four distinct concerns: key-deriv, auth, privacy, PDU.
- **Proposed decomposition:** `v3_usm.go` (usmUser + key derivation), `v3_auth.go` (HMAC + truncation + verify), `v3_priv.go` (encrypt/decrypt + IV), `v3_pdu.go` (`buildV3Response` + scopedPDU). The test tree already mirrors this (`v3_auth_test.go`, `v3_priv_iv_test.go`, `v3_timeliness_test.go`, `v3_context_test.go`, `v3_seclevel_test.go`, `v3_set_test.go`) — the production split lags the tests.
- **Hot-path preservation analysis:** none (SNMP request rate). Invariants: **auth-before-decrypt ordering** (:162–166 drop malformed priv-without-auth before decrypt), **timeliness/anti-replay window** (v3_timeliness), **privParams rand.Read unchecked** (ps-037 A9 — a known bug in this area). Keep the seclevel gate ahead of the crypto in whatever file it lands.
- **Tests + gate:** the six `v3_*_test.go` files already segment by concern; `go test ./pkg/snmp/...` + an snmpv3 authPriv get/getbulk against the agent.
- **Why it matters:** crypto + protocol assembly in one file is hard to review for exactly the ordering bugs (auth-before-decrypt) that matter most; the tests already prove the seam exists.
- **Fix direction:** split by USM/auth/priv/PDU following the existing test partition.
- **Labels:** refactor, class-B, crypto-adjacent.
- **Dedup note:** not previously cataloged.

#### [A10-go-services] F-12 — Giant test files (review-cost, out of heatmap)

- **Severity:** Low · **Confidence:** High · **Dedup tag:** INCREMENT(codex-171-29 test-split note).
- `frr/frr_test.go` **5,920** — the single largest in this group; the seam-specific FRR tests already exist as siblings (`policy_*_test.go`, `bgp_*_test.go`, `static_*_test.go`), so `frr_test.go` is the residual catch-all. Split its `mod`-equivalent per production seam (bgp/ospf/policy/static/managed-section) alongside the `policy_render.go` file split.
- `dhcprelay/relay_test.go` 2,033, `configstore/store_test.go` 2,005, `ipsec/ipsec_test.go` 1,850, `routing/routing_test.go` 1,805 + `tunnel_reconcile_test.go` 1,649 — all >200-test catch-alls; colocate per the production split when each parent file is split (move-with-the-code, don't split tests standalone).

---


### 6.2 Medium confidence (11)

#### [A1-rust-hotpath] F3 — `worker_loop` (~1,300 LOC) fuses cold cadence housekeeping around one hot `poll_binding` call (uncataloged)

- **Title:** `worker/loop_body/mod.rs::worker_loop` is an uncataloged ~1,300-LOC god-function; its per-tick loop body interleaves telemetry publish, ArcSwap generation-refresh (~225 LOC), HA command apply, session reap, CoS-status publish, and delta drain around a single hot `poll_binding` dispatch.
- **Severity:** MED (readability + hot-tick icache; not a correctness risk).
- **Confidence:** MED-HIGH (fn 36–1337; cold blocks are cadence-gated `if elapsed >= INTERVAL` branches, confirmed by grep of the loop body; not in dedup §1b — catalog tracks `worker/mod.rs::BindingWorker`, a different file).
- **Refactor class:** (C) PERFORMANCE-POSITIVE — the cold blocks are already behind cadence gates; extracting them to `#[cold] #[inline(never)]` helpers pulls their `.text` out of the hot tick loop's icache footprint without changing when they run.
- **Dedup tag:** NEW.
- **Evidence** (loop body 240–1337; the hot call is line 783 `poll_binding(...)`, everything else is cadence-gated cold work):
  ```
  258  if loop_now_ns - wr_last_publish_ns >= WR_PUBLISH_INTERVAL_NS { …publish worker-runtime counters… }  // ~100 LOC
  364  let live_validation = shared_validation.load(); … per-tick Arc ptr_eq refresh …                       // generation-refresh
  368  if <generation changed> { …re-derive validation/forwarding/HA/CoS/local-delivery state… }             // ~225 LOC (#2362/#3082/#3527/#2134/#1635/#917/#941)
  594  apply_worker_commands( … )                                                                              // HA cmd apply
  727  reap_expired_sessions( … )                                                                             // session GC
  783  if poll_binding( … ) { … }              // <-- THE hot per-packet dispatch
  834  if loop_now_ns - last_cos_status_ns >= COS_STATUS_INTERVAL_NS { publish_cos_status … }
  846+ drain_and_flush_all! { … }              // #2442 delta-ring drain
  ```
- **Proposed decomposition:** extract cadence-gated blocks to helpers in `worker/loop_body/` siblings, each called once per gate:
  - `publish_worker_runtime(&mut wr_counters, &runtime_atomics, &cold_path_atomics, …)` ← 258–360
  - `refresh_generation_dependent_state(&mut bindings, &shared_*, …)` ← 368–590 (the biggest, ~225 LOC, fires only on config-generation change)
  - `publish_cos_status(...)` and the `drain_and_flush_all!` macro body → a `drain_worker_deltas(...)` fn.
  Keep the `while !stop` driver + the `poll_binding` dispatch + the per-tick `.load()`/`ptr_eq` fast check in `mod.rs`. `setup.rs` (247) and `debug_report.rs` (370) show this submodule already tolerates the pattern.
- **Hot-path preservation analysis:** the `poll_binding` call and the per-tick `.load() + Arc::ptr_eq` short-circuit (#1188 — avoids `load_full()` clone when generation is unchanged) stay inline in the driver. The extracted helpers are entered only when their cadence gate trips, so marking them `#[cold] #[inline(never)]` cannot regress the common tick. The `wr_counters` state-attribution (active/idle-block/idle-spin ns) must stay in the driver (it reads loop-local timing); only the *publish* of the accumulated counters moves. No new alloc (helpers take `&mut` to existing buffers), no lock widening (the ArcSwap loads are unchanged), single-writer worker ownership intact.
- **Tests + gate:** `make test-rust` + `make cluster-deploy` + `make test-failover` (the generation-refresh and HA-command blocks are on the failover/config-apply path). A worker-runtime metrics scrape before/after confirms the publish cadence is unchanged. Ideally `perf stat` on iperf3 to confirm no per-tick regression.
- **Why it matters:** 1,300 LOC of tick loop where ~1,100 is cold housekeeping makes the actual hot dispatch hard to locate and review, and the cold `.text` sits in the same function the branch predictor/icache serve the hot path from.
- **Fix direction:** extract `refresh_generation_dependent_state` first (largest, most self-contained, config-change-only), then the publish/drain helpers.
- **Labels:** refactor, hot-path, rust-dataplane, worker-loop, NEW.
- **Dedup note:** not in dedup §1b/§1f. Catalog D-class agy-171-23 covers `worker/mod.rs::BindingWorker` (the struct), a different file/subject; `worker_loop` in `loop_body/mod.rs` is unlisted.

#### [A2-rust-fwd-frame] F7 — `ForwardingState` god-struct now **64 fields** (was cataloged 55 — regressed)

**Title:** `types/forwarding.rs::ForwardingState` grew from the cataloged 55 to
**64 fields**; the hot/cold split never happened, and its perf rationale is
weaker than cataloged.
**Severity:** Medium · **Confidence:** High
**Refactor class:** (B) mechanical cold-struct extraction — NOT (C) perf (see below)
**Dedup tag:** STATUS-UPDATE (dedup §1b "ForwardingState 55-field 🟡 PARTIAL (reduced)")

**Evidence** (`types/forwarding.rs:14-278`): manual field count = **64**
(catalog said 55). Selected hot/cold fusion:
- HOT (read per packet via ArcSwap load): `routes_v4/v6`, `connected_v4/v6`,
  `neighbors`, `egress`, `ifindex_to_zone_id`, `source_nat_rules`, `static_nat`,
  `dnat_table`, `policy`, `filter_state`, `cos`, `app_catalog`, `tcp_mss_*`,
  `zone_host_inbound`, `ifindex_host_inbound`, `has_wg_tunnels`.
- COLD (config-parity / diagnostics, read rarely or never on the packet path):
  `gre_acceleration` (`#[allow(dead_code)]`, line 235 — "NOT yet read by any
  packet/forwarding path"), `power_mode_disable` (`#[allow(dead_code)]`, 242 —
  "does not currently switch behavior"), `screen_missing_profiles` (219),
  `fabric_skips` (183, diagnostic), `syn_cookie_master_key`, `mirror_configs`.

The "PARTIAL (reduced)" catalog status refers to **file LOC** dropping
1200→1054 (other types were extracted out). The **struct itself regressed**:
field count went UP 55→64.

**Perf-rationale correction (weakens the cataloged Class C):** the catalog
proposes `ForwardingHot + ForwardingCold` "reorder hot fields first" as a cache
win. But nearly every field is a heap-backed `FastMap`/`FastSet`/`Vec`/`Arc` —
the struct is mostly pointers, and each hot lookup chases a pointer to the heap
regardless of field order. Field reordering therefore buys ~nothing in cache
density; the real payoff is **reviewability** and letting the two dead
config-parity bools + diagnostics move out. So classify as **B (mechanical
cold-struct extraction)**, not C.

**Proposed decomposition:** extract a `ForwardingConfigParity` (cold) sub-struct
holding `gre_acceleration`, `power_mode_disable`, `screen_missing_profiles`,
`mirror_configs`, `syn_cookie_master_key` (and any other never-hot config-truth
field), referenced as `forwarding.parity.*`. Do NOT split the hot maps apart —
they're independent heap allocations, no locality gain. This is a large diff
(every `forwarding.<field>` access), so land it opportunistically with F4's
builder split (same PR).

**Hot-path preservation analysis:** the struct is read via `ArcSwap` (no
per-packet clone; `ForwardingState::clone()` happens at fabric-refresh cadence
only, per the `reject_buckets` comment 154-160). Adding `forwarding.parity.field`
is one extra field-of-struct load for cold fields (already off the hot path).
Keep `#[derive(Clone, Default)]`. `ForwardingResolution` (the register-passed
POD, §1f) is unaffected. No `#[repr]`/`size_of` pin required (heap-backed).

**Tests + gate:** refactor-neutral; `make test-rust`. Confirm the two
`#[allow(dead_code)]` bools have no readers before moving (a `grep` +
`cargo build` warning check).

**Why it matters:** a 64-field god-struct populated by a 410-LOC god-function
(F4) is the group's worst reviewability pair; the two dead config-parity bools
sitting in the hot struct are exactly the fusion the catalog wanted removed.

**Fix direction:** `ForwardingConfigParity` cold sub-struct.
**Labels:** god-struct, modularity. **Dedup note:** UPDATE §1b status — struct
field count REGRESSED 55→64; downgrade C→B (perf rationale doesn't hold for
heap-backed fields).

---

#### [A7-go-dpmgr] F-A7-12 — types.go is a 51-struct BPF-mirror dumping ground — split is guardrail-heavy (informational)

- **Severity**: LOW
- **Confidence**: MEDIUM
- **Refactor class**: **B (guardrails)** bordering **D** — every struct carries a C/Go `sizeof` mirror invariant
- **Dedup tag**: **NEW (fresh)**
- **Evidence**: `pkg/dataplane/types.go` 1,056 LOC = **51 `type … struct` + consts, 1 func** (`CurrentSessions`). Structs are organized by domain (Session L6-160, Zone/Policy L162-205, NAT/SNAT/DNAT/NPTv6 L465-700, Screen L715-836, Iface L890-943) and **each carries `Pad`/`PadEvent`/`Pad2` trailing fields with explicit sizeof comments** ("matches the C/Rust 128-byte layout", "keeps the struct 8-byte") — grep shows ~30 `Pad` fields.
- **Proposed decomposition**: `types_session.go` / `types_nat.go` / `types_screen.go` / `types_iface.go` — possible but only worthwhile if paired with the mirror-alignment tests (`bpf_session_value_test.go`, `constants_test.go`) moving alongside.
- **Hot-path preservation**: these are the C/Go struct-mirror types (preservation rule 2). A split MUST carry the `sizeof` comments and any `unsafe.Sizeof`/alignment assertions with each struct; splitting without the tests risks silent ABI drift with the Rust helper.
- **Fix direction**: LOW priority — cohesive-by-invariant; only split if it grows further, and only with mirror tests co-located.
- **Labels**: refactor, class-B, struct-mirror, low-priority
- **Dedup note**: NEW; flagged mainly so a future splitter carries the Pad/sizeof contract.

---

#### [A8-go-daemon-ha] F8 — `daemon_ha.go::reconcileRGState` (250) + `watchClusterEvents` (182)

- **Title:** Two large RG-state god-functions in `daemon_ha.go`.
- **Severity:** Low-Medium.
- **Confidence:** Medium.
- **Refactor class:** (B) — RG transition ordering (rg_active, VRRP priority,
  services) is failover behavior.
- **Dedup tag:** NEW.
- **Evidence:** `reconcileRGState` L555–805 (250), `watchClusterEvents` L167–349
  (182), `warmNeighborCache` L1221 (80). The reconcile drives per-RG
  primary/secondary transitions → `applyRethServicesForRG`/`clearRethServicesForRG`
  → VRRP priority → ip-monitoring gating.
- **Proposed decomposition:** `reconcileRGState` → `computeRGTransitions()` (pure
  diff) + `applyRGTransition(rgID, from, to)`; `watchClusterEvents` → event-type
  handlers. Lower priority than F1/F5.
- **Hot-path preservation analysis:** RG transition is the failover control path.
  Preserve: dual-active overlap is intentional (primary sets rg_active=true
  immediately; secondary defers false until VRRP BACKUP) — a split must not
  serialize/reorder these; `reconcileIPMonGating` is re-driven from here.
- **Tests + gate:** `rg_state_test.go` (929), `per_rg_test.go`; `make test-failover`.
- **Why it matters:** RG reconcile is where HA state becomes dataplane action;
  keeping it monolithic obscures the transition matrix.
- **Fix direction:** Defer behind F1/F5; extract the pure transition-compute first.
- **Labels:** refactor, pkg/daemon, HA.
- **Dedup note:** New; daemon HA files are domain-split but carry these two god-fns.

#### [A8-go-daemon-ha] F9 — `vrrp/manager.go::UpdateInstances` 209-LOC diff/lifecycle

- **Title:** `UpdateInstances` is a 209-LOC instance diff + build-before-teardown
  lifecycle function.
- **Severity:** Low-Medium.
- **Confidence:** Medium.
- **Refactor class:** (B) — build-before-teardown (#2156) + ifindex-drift (#2294)
  + sync-hold re-apply ordering is failover behavior.
- **Dedup tag:** NEW.
- **Evidence:** `func (m *Manager) UpdateInstances` L321–530 (209).
  `openAfPacketReceiver` L879 (154, cohesive cBPF builder). Diffs running vs desired,
  restarts on VIP change (proof-then-commit), in-place priority/preempt/track
  updates, ifindex-drift probe, sync-hold suppression re-apply.
- **Proposed decomposition:** `UpdateInstances` → `diffInstances(desired)` +
  `restartInstanceBuildFirst(old, new)` + `updateInstanceInPlace(old, new)`. Keep
  the build-before-teardown ordering in one helper.
- **Hot-path preservation analysis:** The `m.mu` hold, the "no restart on
  priority/preempt/track change" (no master-down gap), and build-before-teardown
  (new socket opens before old stop — the two `run()` goroutines never overlap for
  one key) are the invariants; a split must keep restart vs in-place as one
  decision under one lock.
- **Tests + gate:** `update_instances_test.go` (567), `manager_reuse_test.go`;
  `make test-failover`.
- **Why it matters:** Instance churn during commit/reconcile is where a split-brain
  or dropped-from-election bug hides (#2156/#2294 both landed here).
- **Fix direction:** Extract the diff and the two lifecycle arms; low urgency.
- **Labels:** refactor, pkg/vrrp.
- **Dedup note:** New; complements codex-171-27 (which targets instance.go, not
  manager.go).

#### [A8-go-daemon-ha] F10 — `daemon_system.go` low-cohesion system-config grab-bag (1,310 LOC)

- **Title:** `daemon_system.go` mixes syslog, timezone, login, ssh, and password
  reconciliation in one file with five ~100–157-LOC functions.
- **Severity:** Low.
- **Confidence:** Medium.
- **Refactor class:** (A) MECHANICAL — independent per-domain reconcilers, no shared
  ordering.
- **Dedup tag:** NEW.
- **Evidence:** `applySyslogConfig` 157, `applySystemLogin` 130, `applySSHConfig`
  129, `reconcileUserPassword` 100, `applySyslogFiles` 95, `applyTimezone` 60 — six
  unrelated system-config domains in one file.
- **Proposed decomposition:** `daemon_system_syslog.go` / `daemon_system_login.go`
  (login + password + ssh) / `daemon_system_timezone.go`. Pure file motion.
- **Hot-path preservation analysis:** None (commit-path config actuation, each
  domain independent). Persistence-class writers (DurableState vs
  AtomicGeneratedConfig) must be preserved per call site.
- **Tests + gate:** `daemon_ssh_test.go` (555); `make test-go`; `make test-deploy`.
- **Why it matters:** Low-cohesion files degrade discoverability; this one is a
  clean, safe mechanical split.
- **Fix direction:** Straight file motion, one PR.
- **Labels:** refactor, pkg/daemon, low-cohesion.
- **Dedup note:** New; smallest-risk item in the group.

#### [A8-go-daemon-ha] F11 — `cluster/status.go` formatting dumping-ground (691 LOC, 8 funcs)

- **Title:** `status.go` is 691 LOC across only 8 functions, dominated by
  `FormatInformation` (263) — a status-string dumping ground.
- **Severity:** Low.
- **Confidence:** Medium.
- **Refactor class:** (A) MECHANICAL — pure formatting, no locking/ordering concern.
- **Dedup tag:** NEW.
- **Evidence:** `FormatInformation` 263, `FormatInterfaces` 117,
  `FormatIPMonitoringStatus` 88, `FormatStatus` 88 — one file, one concern
  (chassis-cluster status rendering) but the functions are individually oversized.
- **Proposed decomposition:** Split `FormatInformation` into per-section builders
  (`formatNodeSection`, `formatRGSection`, `formatMonitorSection`); optionally
  `status_format.go` for the interface/ipmon renderers.
- **Hot-path preservation analysis:** None (CLI/gRPC display path).
- **Tests + gate:** `make test-go`; visual `show chassis cluster information`.
- **Why it matters:** Low, but `FormatInformation` at 263 LOC is a god-fn by the
  >100 rule; splitting is trivially safe.
- **Fix direction:** Section-builder extraction, one PR.
- **Labels:** refactor, pkg/cluster, formatting.
- **Dedup note:** New.

#### [A8-go-daemon-ha] F12 — `ra/sender.go::buildRA` 175-LOC option assembler

- **Title:** `buildRA` is a 175-LOC RA-option assembly function.
- **Severity:** Low.
- **Confidence:** Medium.
- **Refactor class:** (B) — the option set is the change-detection contract
  (`configEqual` must track every field `buildRA` stamps).
- **Dedup tag:** NEW.
- **Evidence:** `func (s *sender) buildRA` L681–856 (175); assembles prefixes,
  RDNSS, NAT64 prefix, MTU, lifetimes, ND timer hints, then `pruneUnmarshalableOptions`.
- **Proposed decomposition:** `buildRA` → `buildPrefixOptions` + `buildDNSOptions`
  + `buildNAT64Option` + base-header assembly. Low urgency.
- **Hot-path preservation analysis:** Per-interface RA build (not per-packet).
  Preserve: the RFC 4861 §4.6.2 preferred≤valid clamp (#2271); the #3895
  per-option `pruneUnmarshalableOptions` backstop; and the invariant that EVERY
  wire-stamped field is mirrored in `configEqual` (ra.go) — a split must not let a
  field escape the change-detection list (the #4119/#4307/#4570/#4590 class).
- **Tests + gate:** `serialize_test.go` (2,648), `sender_marshal_*_test.go`;
  `make test-go`.
- **Why it matters:** Low, but the field-list ↔ configEqual coupling makes even a
  formatting split worth doing carefully.
- **Fix direction:** Defer; if touched, keep configEqual in lockstep.
- **Labels:** refactor, pkg/ra.
- **Dedup note:** New.

#### [A9-go-api-cli] F8 — `security.go` policy/match-policy handlers are 260–277 LOC (secondary)

- **Severity:** Low · **Confidence:** Medium · **Refactor class:** (A) MECHANICAL
- **Dedup tag:** NEW
- **Evidence:** `pkg/api/security.go` `policiesHandler`(138→398 = 260 LOC) and
  `matchPoliciesHandler`(505→782 = 277 LOC) each build the full policy/match projection inline.
  Policy-detail projection is the subject of a large prior finding cluster (codex-125/127/128,
  "policy-detail rendering → shared reusable module") — these REST handlers are additional copies
  of that projection.
- **Proposed decomposition:** fold the policy projection into the shared policy-render module the
  codex-125 cluster proposes; REST handler becomes marshal-only.
- **Hot-path preservation:** N/A.
- **Tests + gate:** `pkg/api/security_*_test.go` set; `make test-go`.
- **Why it matters:** policy projection correctness (exclusion/logging/IDs/scheduler) already had
  ~20 findings for inverting/collapsing fields across surfaces; every extra copy is another vector.
- **Fix direction:** subsume under the codex-125/127 policy-render dedup, not a standalone split.
- **Labels:** god-function(mild), dedup-adjacent
- **Dedup note:** relates to codex-125/127/128 policy-render cluster; noting the REST copies.

#### [A9-go-api-cli] F9 — grpcapi `Server` accessor-`Fn` closure cluster (minor god-struct)

- **Severity:** Low · **Confidence:** Medium · **Refactor class:** (A) MECHANICAL
- **Dedup tag:** NEW
- **Evidence:** `pkg/grpcapi/server.go::Server` has ~40 fields, of which 13 are `…Fn func() …`
  DI closures (`rpmResultsFn, ipmonStatusFn, natPoolAlarmsFn, feedsFn, feedOverlayFn,
  lldpNeighborsFn, ddnsStatsFn, ddnsOwnedRecordsFn, surfaceADDNSStatsFn/StatusFn/ForceFn,
  flowCollectorHealthFn, …`) plus test-seam `Fn`s. Same accretion shape the daemon god-struct
  fix (#4407) grouped into sub-structs.
- **Proposed decomposition:** group the observability/status closures into a `statusProviders`
  sub-struct (`s.providers.rpmResults()` …), matching the #4407 field-grouping pattern. Low value.
- **Hot-path preservation:** N/A.
- **Tests + gate:** `make test-go`.
- **Why it matters:** minor — the struct is the service aggregation root; grouping improves
  readability but is not urgent. Recorded to complete the sweep (task explicitly asked whether the
  gRPC service is a god-service — answer: NO, it is well file-split by RPC domain; only the
  provider-closure cluster is a mild smell).
- **Fix direction:** optional sub-struct grouping; defer.
- **Labels:** god-struct(mild), presentation-plane
- **Dedup note:** NEW; analogous to #4407 field-grouping.

#### [A10-go-services] F-8 — ddns/manager.go: lease-DDNS Manager (74-field struct + `policyFromConfig` 167 / `ReconcileScoped` 144)

- **Title:** The lease-driven DDNS `Manager` is a second large DDNS monolith beside surface_a.go.
- **Severity:** Low→Medium
- **Confidence:** Medium
- **Refactor class:** **A/B (mechanical split; reconcile ordering is guarded)**
- **Dedup tag:** **NEW** (uncataloged; manager.go 1,359 LOC — the catalog only named `surface_a.go`).
- **Evidence:** `type Manager struct` spans 74 lines; `policyFromConfig` (:153) 167 LOC (config→policy compile), `ReconcileScoped` (:551) 144 LOC (per-scope reconcile), `upsertLocked` (:1050) 116, `deleteOwnedLocked` (:1166) 69. Same shape as surface_a.go (reconcile/upsert/withdraw + a big config-compile fn) but tracked nowhere.
- **Proposed decomposition:** `manager_policy.go` (`policyFromConfig` + policy types), `manager_reconcile.go` (`ReconcileScoped`), `manager_records.go` (`upsertLocked`/`deleteOwnedLocked`). Parallels the proposed surfacea/ split.
- **Hot-path preservation analysis:** none (reconcile pace ~30s). Invariants: **skippedNoBackend accounting** (:upsertLocked mirrors surface_a's #2691 P3 — a half-configured provider must not advance ownership) and **HA per-RG writer gate**. Preserve the skip-before-ownership-write ordering.
- **Tests + gate:** `manager_test.go` (887), `manager_inc2_test.go` (873), `scope_test.go`. Gate: `go test ./pkg/ddns/...` + a lease-DDNS upsert/withdraw end-to-end.
- **Why it matters:** it's the same class of monolith as the cataloged surface_a.go but uncaptured — coverage-proof value.
- **Fix direction:** mechanical file split by policy/reconcile/records.
- **Labels:** refactor, class-A/B, monolith.
- **Dedup note:** sibling of codex-171-28 (surface_a) but a distinct, uncataloged file.


### 6.3 Low confidence — smells, marginal splits, and DO-NOT-SPLIT negative results (25)

#### [A1-rust-hotpath] F5 — `reject_reply.rs`: production is cohesive (D-NEGATIVE on split); the 2,174 REFACTOR tier is 81% inline tests

- **Title:** `poll_descriptor/reject_reply.rs` reads as a REFACTOR-tier monolith (2,174) but production is 414 LOC across 4 tightly-related fns; do NOT split production — relocate the 1,760-LOC inline `mod tests`.
- **Severity:** LOW.
- **Confidence:** HIGH (test block 415–2174, 25 tests; 4 prod fns enumerated).
- **Refactor class:** (A) MECHANICAL (test move) + (D) DO-NOT-SPLIT (production).
- **Dedup tag:** NEW (reject_reply.rs is uncataloged — brief flagged it as a "fresh candidate").
- **Evidence:**
  ```
  43   enqueue_policy_reject_reply   (~72 LOC)
  116  enqueue_deny_reply            (~50)
  167  deny_reply_and_emit          (~47)
  215  enqueue_reject_reply         (~199)   <- largest, near the 200 cue but cohesive
  415  #[cfg(test)] mod tests { … }  (1,760 LOC, 25 tests)
  ```
  The 4 fns share one responsibility: synthesize a policy/filter `reject` reply (TCP RST or ICMP/ICMPv6 unreachable), applying the budget gate, per-zone reject rate-limiter (#3618), output-filter classification, and RT_FLOW reject→deny truthfulness downgrade (#3615). `enqueue_reject_reply` (199 LOC) is the shared build core the other three funnel into.
- **Proposed decomposition:** move `mod tests` (415–2174) to `poll_descriptor/reject_reply/tests.rs` (or `reject_reply_tests.rs` sibling). File drops to ~414 LOC — off the REFACTOR heatmap. Leave the 4 production fns together: they are one cohesive reply-synth unit and splitting `enqueue_reject_reply` out from its three callers would fragment the budget/rate-limit/output-filter gate sequence that must stay in lockstep (a #3615 truthfulness invariant).
- **Hot-path preservation analysis:** cold path only (generated-reply, session-miss/terminal). `size_of::<UserspaceDpMeta>()` at 461 is inside `enqueue_reject_reply`'s wire-frame build — a wire-format constant, stays with production. No hot-path impact either way.
- **Tests + gate:** the 25 tests move verbatim; `make test-rust`. They pin the reject truthfulness / per-zone isolation / VLAN-logical-ifindex (#3035/#3976) contracts.
- **Why it matters:** without correcting for inline tests, an auditor re-flags reject_reply.rs as a 2.1K monolith needing a production split — it doesn't. The honest state is 414 cohesive prod LOC.
- **Fix direction:** one-line-of-effort test relocation; no production change.
- **Labels:** test-colocation, rust-dataplane, D-negative, NEW.
- **Dedup note:** uncataloged. Recording so the next auditor doesn't propose a production split; the only action is the test move.

#### [A1-rust-hotpath] D-class confirmations (re-verified, no action)

- `poll_descriptor/flow_cache_hit.rs::stage_flow_cache_hit` (456 LOC) — 90%+ established-flow fast path; splitting kills inlining/icache. **D confirmed** (ps-010/agy-171-24).
- `worker/mod.rs::BindingWorker` (1,556 prod) — already field-grouped via #959 (WorkerXskRings/Umem/TxPipeline/Cos/Scratch); further struct split → pointer-chase/cache-miss on per-packet state. **D confirmed** (agy-171-23).
- `flow_cache.rs` (997 prod) — cohesive 4-way set-associative cache with `const _: () = assert!` power-of-two/ways layout pins (lines 18–20); a cohesive data structure, not a dumping ground. **D / clean.**
- `poll_descriptor/nat_exception.rs` — correctly `#[cold] #[inline(never)]` cold SNAT extraction (#1697); the template for F1's `nat_prerouting.rs`. **Clean.**
- `shared_ops.rs` (1,131 prod) — cohesive HA shared-session-map ops under the #2402 poison-recovery policy; sub-1500, single responsibility. `prewarm_reverse_synced_sessions_for_owner_rgs` (167 LOC) is a >150 cue but a cohesive failover-critical routine (#4069). **Near-clean; no split.**

#### [A2-rust-fwd-frame] F9 — D-class confirmations (do-not-split) + minor cold-file note

**Title:** Several cataloged/fresh files verified D-class (cohesion/perf beats
modularity); one minor cold-pool file note.
**Severity:** Informational · **Confidence:** High
**Refactor class:** (D) · **Dedup tag:** D-NEGATIVE

**Confirmations:**
- **`frame/inspect.rs` (1810 prod)** — dedup §1f codex-171-31 CONFIRMED. It is
  ~40 small (<80 LOC) packet-inspection primitives sharing offset/bounds
  conventions (`frame_l3/l4_offset`, fragment detection, term-match extract,
  ICMP-error-suppression predicates that must agree — `dest_is_multicast`,
  `*_directed_broadcast`, `source_is_invalid_for_icmp_error`,
  `l2_dst_is_group_or_broadcast` — and session-flow parse). No god-function
  (largest, `parse_session_flow_from_bytes`, ~140 LOC < 150). Splitting risks
  the fail-closed offset-locality contract. **Do not split.**
- **`umem/mod.rs::BindingLiveState` (266-776)** — dedup §1f codex-173-22
  CONFIRMED. A single-owner per-binding aggregator of ~60 `AtomicU64`/`AtomicU32`
  counters + `Mutex<SharedUmemLiveStatus>` + `ArcSwap` snapshots + TX-admission
  state; one worker writes, control thread reads. Splitting adds pointer-chase /
  false-sharing. **Do not split the struct.** Minor: the cold `WorkerUmem` /
  `WorkerUmemPool` mmap-lifecycle (35-175, ~140 LOC) could move to a sibling
  `umem/pool.rs` (there's already `umem/mmap.rs`) to leave `mod.rs` the
  BindingLiveState concern — Class A, low value, file is under 2000 prod. Note
  only.
- **`frame/build/*` + `frame/rewrite/*`** — dedup §1f codex-173-25 CONFIRMED:
  concrete per-family (v4/v6) build/rewrite codegen, correct split already.
- **`frame/wg.rs::wg_encap_frame` (305-557, ~252 LOC)** — a hot per-WG-packet
  encap builder (strip L2 → AllowedIPs LPM peer select → pad-aware MTU guard →
  outer header → crypto encrypt → checksum). Cohesive single-buffer crypto+build
  pipeline; **D** (splitting breaks the single output `Vec` alloc discipline and
  inlining). The file is FRESH but NOT a monolith — ~608 prod LOC (rest inline
  tests). Flag `frame/wg.rs` tests (952-1561) for colocation, not the code.
- **`frame/mod.rs` (1699 prod)** — the hot per-packet frame-mutation core
  (`build_forwarded_frame*`, `rewrite_apply_v4/v6`, `apply_nat_ipv4/ipv6`,
  checksum). Three sub-concerns (build / L2-rewrite / NAT-apply) that ARE
  separable with `#[inline]` guards, but it already delegates family helpers to
  `build/`+`rewrite/` (D), and `apply_nat_ipv6` (~133 LOC) is a cohesive
  per-packet header-walk+incremental-checksum. Leave as mostly-D; if it grows
  past 2000 prod, split `apply_nat_*` to `frame/nat_apply.rs` with
  `#[inline]`-preserved family fns + a `cargo asm` gate.
- **`forwarding/host_inbound.rs::classify_system_service` (97-284, ~187 LOC)** —
  a long token→signature match on the COLD config-build path. Borderline
  god-function but it's a flat, readable match table (each arm a token→port/type
  mapping). Could be data-driven but the current form is clear; **low priority**,
  not worth churning a security-sensitive classifier. Note only.

**Why it matters:** documents that re-proposing these splits is a
finding-quality miss (per the audit's D-class rule), and that the two FRESH
neighbor/wg files owe their `[REFACTOR]`/`[WATCH]` flags to test inflation, not
production monolith-ness.

**Fix direction:** none (D) except the optional `umem/pool.rs` cold split and
the wg/neighbor test colocation. **Labels:** d-class, do-not-split.
**Dedup note:** confirms codex-171-31, codex-173-22, codex-173-25; adds
`frame/wg.rs` + `frame/mod.rs` as fresh D verdicts.

---

#### [A3-rust-cos-tx] F4 — NEW/STATUS-UPDATE: `cold_path_hist.rs` WATCH size is ~48% inline test block (D-class holds for the structs)

- **Title**: `cold_path_hist.rs` — colocate the inline `mod tests` to a `#[path]` sibling; D-class production structs stay
- **Severity**: Low
- **Confidence**: High
- **Refactor class**: **(A) MECHANICAL/SAFE**
- **Dedup tag**: D-NEGATIVE (structs) + NEW (test colocation)
- **Evidence**: file is 1,867 LOC (`[WATCH] 1,745`). Production code ends at `impl WorkerColdPathCounters` (~L950); `#[cfg(test)] mod tests` spans **L952–1866 (~915 LOC, ~48% of the file)** — an INLINE test block, unlike every other file in this module group (`dispatch_tests.rs`, `cos_classify_tests.rs`, `queue_service/tests.rs`, etc. are all `#[path]` siblings). Moving it to `cold_path_hist_tests.rs` drops the production file to ~950 LOC — off WATCH entirely.
- **D-NEGATIVE confirmation (codex-171-30)**: CONFIRMED. The production structs must NOT split: `WorkerColdPathAtomics` `#[repr(C, align(64))]` (602) with hot fields pinned at cacheline 0; `WorkerColdPathCounters` `#[repr(C)]` (852) with the verified offset map (sample_phase@0 … clock_source@32, builder_collision@33); the `offset_of!` layout-pin tests (962–995); the `ClockSource` `#[repr(u8)]` (387); the seqlock publish/snapshot with the **#1643 `fence(Acquire)`** discipline (776) — which lease.rs’s `snapshot_epoch_v8` explicitly cites as "the verified-correct reference". TSC `sample_tsc_start/end` fence recipe (316–349) is co-located by design. Keep all of it together.
- **Proposed decomposition**: `#[path = "cold_path_hist_tests.rs"] mod tests;` — mechanical move of L952–1866.
- **Hot-path preservation analysis**: none affected — `#[cfg(test)]` code never ships. The `offset_of!` pins move with the tests and continue to guard the repr(C) layout.
- **Tests + gate**: `make test-rust` (test discovery unchanged under `#[path]`). Gate: `make audit-check`.
- **Why it matters**: the file’s WATCH flag is an artifact of it being one of the last inline-test holdouts in the tree; colocating aligns it with the project pattern and un-flags it, without touching the D-class seqlock/repr structs.
- **Fix direction**: mechanical; bundle with the next cold-path change.
- **Labels**: refactor, test-colocation, cold-path
- **Dedup note**: refines codex-171-30 — the D verdict is right for the STRUCTS; it does not cover the colocatable inline test mass.

#### [A3-rust-cos-tx] D-NEGATIVES confirmed (no action)

- **`tx/rings.rs`** (415, codex-173-23) — CONFIRMED D. Single-owner/single-free UMEM frame lifecycle: `reap_tx_completions`, `drain_pending_fill`, `maybe_wake_rx/tx`, `recycle_completed_tx_offset`, `apply_prepared_recycle`. Cohesive, no god-fn, small inline tests. Keep.
- **`types/cos.rs::FlowFairState`** (codex-173-24) — CONFIRMED D (see F3): parallel bucket-array layout + `new_boxed` placement + power-of-two const-assert are load-bearing.
- **`cold_path_hist.rs` production structs** (codex-171-30) — CONFIRMED D (see F4): repr(C,align(64)) + offset asserts + #1643 seqlock fence must stay together.
- **`tx/dispatch/{cos,shared_recycle,slow_path}.rs`, `tx/transmit/*`, `cos/queue_ops/*`, `cos/queue_service/{service,drain,submit_*}.rs`** — post-split siblings, cohesive; the #4408 / #1035 decompositions already peeled these correctly. No re-proposal.

#### [A4-rust-session-policy] F9 — nat/destination.rs: fresh read — cohesive single-domain, low priority

- **Severity:** Low · **Confidence:** Medium · **Refactor class:** D (or low-B) · **Dedup tag:** NEW (fresh, not individually cataloged)
- **Evidence:** 1,088 LOC (below WATCH), all one domain: `DnatTable`/`DnatEntry`/`DnatKey`/`DnatValue`/`DnatProtoPortKey`/`DnatPrefixSlot`. `from_snapshots`(285=**234 LOC**, cold compile) is the only large body; the hot `lookup_with_counter_scoped`(565=139) + LPM helpers (`match_prefix_lpm`/`match_prefix_slots`/`insert_prefix_slot`) are appropriately small and locality-tight.
- **Proposed decomposition:** none needed now. If it grows, peel the cold builder into `destination_build.rs` (from_snapshots + insert_entry + insert_prefix_slot), keep the DnatTable lookup/match hot path in `destination.rs`.
- **Hot-path preservation:** `lookup_with_counter_scoped` + LPM must stay co-located (prefix-slot arrays + LPM walk are one cache-local structure).
- **Tests + gate:** `nat/tests_destination.rs`/`tests_dnat_proto.rs` (already split); DNAT hit-counter end-to-end.
- **Why it matters:** confirms destination.rs is NOT a monolith concern (answers the A4 "check destination.rs freshly" ask) — the only smell is the 234-LOC cold builder.
- **Fix direction:** leave; opportunistic builder-peel only if a feature adds ~200 LOC.
- **Labels:** modularity-negative. **Dedup note:** fresh; no prior finding beyond #4409's file-level mention.

#### [A4-rust-session-policy] F10 — screen/mod.rs: D-class PARTIALLY STALE — `check_packet_with_zone_id_opts` is a ~330-LOC inline god-fn

- **Severity:** Medium · **Confidence:** High · **Refactor class:** B · **Dedup tag:** NEW / D-correction (catalog 1f "already decomposed")
- **Evidence:** file grew 1,479→1,540. `check_packet_with_zone_id_opts` (777) runs to its `Pass`/`SynCookieBypass` return at ~1106 = **~330 LOC** in one function (next fn `check_flowless_screens` at 1151). Stateless checks ARE extracted (`stateless::check_land/tcp_flag/ping_of_death/teardrop/icmp_fragment/source_route`, 809–826). But the **rate-flood + SYN-flood-sketch + SYN-cookie enforcement body is still inline** (847–1106, ~260 LOC): icmp/udp flood via `self.icmp_flood_drop`/`udp_flood_drop`, then a large inline SYN-flood block (per-zone alarm, per-source sketch `syn_src_sketch`, per-dest, cookie-active gating). The `screen/` dir ALREADY has `rate.rs`, `syn_rate.rs`, `syncookie.rs` as homes — the enforcement was never hoisted into them. This is the prior campaign's "inlined ~110-line SYN-flood enforcement," now grown to ~260.
- **Proposed decomposition:** hoist the rate-flood/syn-flood/syn-cookie enforcement into `screen/syn_rate.rs` + `screen/rate.rs` as `ScreenState` methods (e.g. `run_rate_flood_checks(&mut self, zone, zone_id, pkt, now_ns, now_secs) -> Option<ScreenVerdict>`), leaving `check_packet_with_zone_id_opts` a ~60-LOC dispatcher: none-profile guard → stateless → `skip_rate_flood` early return → rate-flood delegate → cookie-bypass result.
- **Hot-path preservation:** screen runs on the first packet of a flow (not per established packet), so this is review-cost not per-packet latency. Preserve the #2209 disjoint-field borrow pattern (`&self.profiles[zone]` held across `&mut self.<counter>`): the delegate must copy the small scalar thresholds out of `*profile` first (as the current code already does at 854–857) so the `profiles` borrow is released before `&mut self` SYN-cookie calls. Do NOT introduce a per-check trait registry (hot-path note forbids a dynamic stage registry).
- **Tests + gate:** `screen/tests.rs` (5,395) syn-flood/flood/cookie clusters; `make test-rust`; exercise syn-flood + icmp/udp-flood from a test host (drop counters advance).
- **Why it matters:** the catalog marks screen/mod.rs D "already decomposed" — true for stateless checks, **false for the rate/cookie body**; a reviewer trusting the D-label would miss the largest remaining screen god-fn.
- **Fix direction:** extract `run_rate_flood_checks` into the existing `syn_rate.rs`.
- **Labels:** modularity, D-correction. **Dedup note:** refines catalog 1f "screen/mod.rs already decomposed" — accurate only for stateless.

#### [A4-rust-session-policy] F11 — screen/scan.rs: fresh — cohesive generic, test-heavy (not a production monolith)

- **Severity:** Low · **Confidence:** High · **Refactor class:** D · **Dedup tag:** NEW (fresh, not cataloged)
- **Evidence:** 1,213 LOC but production is only ~195–590 (~400 LOC): a generic `ScanCore<T>` (216) with `check`/`evict_stalest_in_zone`/`cleanup`/`take_pressure_event`, wrapped by `PortScanTracker`/`IpSweepTracker`. The remaining ~620 LOC (597–1213) is one inline `mod tests` (~30 tests). The generic core is shared by both trackers — splitting it would duplicate the bounded-eviction logic.
- **Proposed decomposition:** none for production (cohesive by design — one source of truth for the bounded per-zone scan sketch, per engineering-style "one source of truth for every formula"). The inline test block is within the project's per-file `mod tests` pattern; only split if it crosses the >200-test rule (it is ~30).
- **Hot-path preservation:** `ScanCore::check` runs on the new-flow scan/sweep decision (`scan_sweep_drop_on_new_flow`); keep it monomorphized per tracker (generic `T`), no boxing.
- **Tests + gate:** as-is.
- **Why it matters:** answers the A4 "scan.rs fresh" ask — it is NOT a monolith; the LOC is test-dominated.
- **Fix direction:** leave.
- **Labels:** modularity-negative. **Dedup note:** fresh D-negative.

#### [A5-rust-control] A5-F3 — protocol/binding.rs + control.rs: large but single-schema-dominated (D-NEGATIVE)

- **Title:** protocol wire DTOs are big because of one dominant status struct each, not a god-function or dumping ground
- **Severity:** Low (informational negative)
- **Confidence:** High
- **Refactor class:** (D) DO-NOT-SPLIT (further)
- **Dedup tag:** D-NEGATIVE
- **Evidence:** `binding.rs` (1168) holds 7 DTOs — `WorkerRuntimeStatus`, `HAGroupStatus`, `QueueStatus`, `BindingStatus` (293–832, **~539 LOC of serde fields**), `BindingCountersSnapshot`, `ExceptionStatus`, `SessionDeltaInfo` — dominated by the one `BindingStatus` schema (every counter gauge/socket field/flow-cache/histogram the server README's `zero_unbound_slot` enumerates). `control.rs` (1040) holds 15 DTOs dominated by `ProcessStatus` (101–592, **~491 LOC**). Both are the Go↔Rust wire SSOT and were ALREADY domain-split in #1325 (`mod.rs` docstring documents snapshot/cos/nat/security/control/binding/resolution). The awk that flagged a "710-LOC `bool_is_false`" and "410-LOC `From<SlowPathStatus>`" was mis-attributing struct-field runs to the preceding serde-helper/`From` line; the actual `From<&BindingStatus>` is 188 LOC and `From<SlowPathStatus>` is ~27 LOC.
- **Hot-path preservation analysis:** These are the snapshot-decode boundary. `validated.rs`-style range ceilings live in `afxdp/forwarding_build/validated.rs` (the only `validated.rs` in the crate; it is 105-LOC-adjacent and cohesive — not a monolith). The concern per the dedup §2 boundary note is that a single oversized field kills the whole decode; keeping each schema in one file is what makes the u16/u8 ceilings auditable in one place. Splitting `BindingStatus`/`ProcessStatus` field-groups into sub-files would fragment the wire contract for near-zero modularity gain.
- **Tests + gate:** `protocol/tests.rs` (2334) already pins wire shapes; no change.
- **Why it matters:** Records the honest negative so a future pass doesn't re-propose a `protocol/binding_*.rs` field-split. Per refactoring-audit.md "when NOT to refactor: LOC dominated by one cohesive schema definition."
- **Fix direction:** none required. If binding.rs crosses ~1500, the only clean seam is peeling `WorkerRuntimeStatus`/`HAGroupStatus`/`QueueStatus` into `binding/{worker,ha,queue}.rs` and leaving `BindingStatus` whole — low value, defer.
- **Labels:** protocol, wire-SSOT, D-class
- **Dedup note:** Go-side `pkg/dataplane/userspace/protocol.go` (2901, codex-171-11, top WATCH) is a SEPARATE finding for a different (Go) surface; this negative is only about the Rust `protocol/` tree.

#### [A5-rust-control] A5-F4 — xsk_ffi.rs: cohesive per-type AF_XDP FFI wrapper (D-NEGATIVE)

- **Title:** `xsk_ffi.rs` is the crate's single AF_XDP unsafe boundary; unsafe surface is small per impl and the ring-writer invariant argues against scattering
- **Severity:** Low (informational negative)
- **Confidence:** High
- **Refactor class:** (D) DO-NOT-SPLIT (with a low-value A seam noted)
- **Dedup tag:** D-NEGATIVE
- **Evidence:** `xsk_ffi.rs` (1462) is a textbook one-type-per-concept FFI wrapper: `Errno`, `UmemConfig`, `SocketConfig`, `IfInfo`, `Umem`(+Drop), `Socket`, `User`, `DeviceQueueRings`, `DeviceQueue`(+Drop), `XdpStatisticsV2`, `RingRx`, `RingTx`, `ReadRx`(+Drop), `WriteTx`(+Drop), `WriteFill`(+Drop), `ReadComplete`. 72 unsafe sites, but each lives in a small self-contained impl (largest fn `create_xsk_binding_impl` 105; most <40). The README's critical invariant — producer-ring writers `WriteTx`/`WriteFill` are append-safe across multiple `insert()` on one reservation (#2383) — is a HOT-path (per-TX) correctness property that must be read together with the ring structs.
- **Hot-path preservation analysis:** `WriteTx::insert`/`WriteFill::insert`/`commit`/`Drop` are on the TX/fill submission path (per batch). Splitting into `xsk_ffi/{umem,device_queue,rings,socket,stats}.rs` is mechanically possible (each type is already isolated) but scatters the four ring writers whose bounded-reservation invariant is one contract, and fragments the 72 unsafe sites the auditor wants to review as one boundary. Same crate → inlining preserved either way, so there's no perf gain to justify the audit-cohesion loss.
- **Tests + gate:** inline tests (`private_constructor_rings_borrow_umem_ring_boxes`, ring reserve tests) stay with their types.
- **Why it matters:** Prevents a re-proposal of a low-value FFI file-split. The unsafe-surface cohesion is a feature: one file to grep for the whole AF_XDP boundary.
- **Fix direction:** none required. If it crosses ~1800, split by type family (`umem`, `device_queue`, `rings`, `stats`) but keep all four ring writers in one `rings.rs`.
- **Labels:** ffi, unsafe, af_xdp, D-class

#### [A5-rust-control] A5-F5 — state_writer.rs: production code well-factored; bulk is inline tests (D-NEGATIVE)

- **Title:** `state_writer.rs` is 1280 LOC but its production surface is small and cohesive; the size is a colocated inline test block
- **Severity:** Low (informational negative)
- **Confidence:** High
- **Refactor class:** (D) DO-NOT-SPLIT (note: colocate inline tests)
- **Dedup tag:** D-NEGATIVE
- **Evidence:** Largest PRODUCTION fns are modest — `new` 63, `sweep_stale_temps` 61, `instance_is_alive` 52, `instance_from_temp_name` 47, `persist_with_mode` 46, `real_proc_start_time` 29, `sync_all` 30. Every larger span (75/74/59/57/44) is a `#[test]` fn (`sweep_removes_dead_pid_orphan…`, `runtime_io_uring_failure_demotes_to_sync_permanently`, `two_concurrent_writers_never_publish_crossed_bytes`, …). Single responsibility: atomic state-file publish with an io_uring→sync permanent demotion (`WriteMode`) and PID-start-time orphan-temp sweep. No god-function.
- **Hot-path preservation analysis:** Cold (state export, not per-packet). io_uring write path + sync fallback + the demote-on-failure invariant is cohesive; do not fracture.
- **Tests + gate:** the inline `mod tests` could move to `state_writer_tests.rs` per the project's colocation pattern (engineering-style: >200 unrelated tests colocate) — but this block is topical (all about the writer) and modest, so it is a *style* nit, not a monolith.
- **Why it matters:** Honest negative — 1280 raw LOC looks like a REFACTOR candidate but is ~half tests on one cohesive subject.
- **Fix direction:** optional test colocation only; production code untouched.
- **Labels:** state-writer, io_uring, D-class, test-colocation

#### [A5-rust-control] A5-F6 — userspace-xdp/src/lib.rs: verifier-constrained eBPF shim (D-NEGATIVE)

- **Title:** the retained AF_XDP shim is verifier-shaped; `try_xdp_userspace` (342) is a bounded program entry, not an ordinary god-fn
- **Severity:** Low (informational negative)
- **Confidence:** High
- **Refactor class:** (D) DO-NOT-SPLIT
- **Dedup tag:** D-NEGATIVE
- **Evidence:** `lib.rs` (1541) is `#![no_std] #![no_main]` with a `#[panic_handler]`, `#[map]` static `HashMap`s sized by `MAX_INTERFACES` (threaded from `bpf/headers/xpf_common.h`), and `xdp_action` returns. Largest fns: `try_xdp_userspace` (405–747, **342**), `classify_native_gre_inner_ipv4/v6` (94/87), `parse_ipv6` (91), `parse_ipv4` (50), `parse_l4` (46), `record_trace` (55). Per `docs/refactoring-audit.md`, BPF/verifier code splits via tail-call decomposition or shared-header helpers, NOT ordinary function extraction; the 512-byte combined stack and 1M-insn cap (CLAUDE.md "make generate" gate) constrain the shape. Branch-merge range loss (re-read `data`/`data_end`) forces the long linear entry.
- **Hot-path preservation analysis:** This IS the kernel dataplane steering program. Any restructure must re-pass the pinned-toolchain kernel-verifier gate (`pkg/dataplane/build-userspace-xdp.sh`); an unpinned split already once blew the insn cap and took both cluster dataplanes down (CLAUDE.md #1864). Do not touch for modularity.
- **Note (not a modularity finding):** `MAX_EXT_HDRS = 6` (line 33) vs the dataplane's canonical `MAX_IPV6_EXT_HEADERS = 8` — this is the already-cataloged ps-037 A1 / #4555 parity gap (dedup §3), not a refactor item.
- **Fix direction:** none. Record as verifier-forced shape.
- **Labels:** ebpf, xdp-shim, verifier, D-class

#### [A5-rust-control] A5-F7 — coordinator/mod.rs: Coordinator root is cohesive; two ~160-LOC lifecycle fns + 227 LOC of debug summaries (LOW)

- **Title:** `coordinator/mod.rs` is below threshold and per-responsibility cohesive; only optional debug-summary peel
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL/SAFE (optional)
- **Dedup tag:** NEW
- **Evidence:** 948 LOC. Real large fns (after correcting visibility-regex misses): `queue_warm_pass` (639–806, **167**, #1636 proactive neighbor warm), `stop_inner` (424–585, **161**, teardown sequence), `wg_endpoint_set_summary` (57–177, 120) + `fabric_skip_set_summary` (177–210, 107) — both pure debug-string builders — `apply_manager_neighbors` (54, NOT the 452 an earlier miscount reported), `replay_synced_sessions` (27, NOT 229). The Coordinator struct is 210–265; the `coordinator/` directory is already well-decomposed into 16 files (wg_control, status, tunnel_supervision, cos_leases, refresh_bindings, snapshot_refresh, inject, …).
- **Proposed decomposition:** (optional) move `wg_endpoint_set_summary` + `fabric_skip_set_summary` (227 LOC of pure formatting) to `coordinator/debug_summary.rs`; consider `queue_warm_pass` → `coordinator/neighbor_warm.rs`. `stop_inner` is a single cohesive teardown ordering (resolver-join-before-worker-stop is load-bearing, documented inline) — keep whole.
- **Hot-path preservation analysis:** All cold (reconcile/teardown/warm). No packet path. `stop_inner`'s join-before-stop ordering is a correctness invariant — do NOT reorder in any extraction.
- **Tests + gate:** coordinator/tests.rs covers lifecycle; summary formatters are pure and unit-testable.
- **Why it matters:** Minor; flagged so the two large formatters don't accrete. File is not a monolith.
- **Fix direction:** low-priority formatter extraction; defer.
- **Labels:** coordinator, low, debug-summary

#### [A5-rust-control] A5-F8 — coordinator/tunnel_supervision.rs: parallel local-tunnel vs wg-control-thread lifecycles (LOW / DRY)

- **Title:** two near-identical supervision lifecycles (local-tunnel sources, wg-control threads) coexist in one 960-LOC file
- **Severity:** Low
- **Confidence:** Medium
- **Refactor class:** (A) MECHANICAL/SAFE
- **Dedup tag:** NEW
- **Evidence:** `spawn_one_local_tunnel_source` (157) ‖ `spawn_one_wg_control_thread` (96); `reconcile_local_tunnel_sources` (73) ‖ `spawn_wg_control_threads` (79); `prune_local_tunnel_sources_for_snapshot` (54) ‖ (wg prune); `reconcile_local_tunnel_liveness` (40) ‖ (wg liveness); `local_tunnel_tombstone_respawn_coherent` (63) ‖ `wg_tombstone_respawn_coherent` (47). The tombstone/respawn/liveness/prune pattern is duplicated per source-kind.
- **Proposed decomposition:** split `tunnel_supervision/{local.rs,wg.rs}.rs` OR (better) extract the shared spawn/tombstone/prune/liveness state-machine into a generic `SupervisedSource` trait/helper so both kinds share the tombstone-respawn-coherent logic (the two `*_tombstone_respawn_coherent` fns are the same algorithm).
- **Hot-path preservation analysis:** Cold (config-apply/reconcile). Both lifecycles spawn/join OS threads; no packet path. The #1881/#1866 tombstone semantics ("stop then join live handles, clear tombstones, re-legitimate next reconcile") must be preserved identically for both kinds — a shared helper actually reduces the risk of the two drifting.
- **Tests + gate:** `local_tunnel_tombstone_respawn_coherent` / `wg_tombstone_respawn_coherent` inline tests pin both; a shared helper needs both to stay GREEN.
- **Why it matters:** DRY — two copies of a subtle tombstone/liveness state machine is the class that drifts (the wg copy could miss a fix landed on the local copy).
- **Fix direction:** shared supervision helper; then per-kind thin wrappers.
- **Labels:** coordinator, tunnel, wg, DRY, low

---

#### [A5-rust-control] wg/engine.rs (1805) — STATUS-UPDATE (agy-171-20/codex-171-9) + NEW hot/cold boundary detail — Class B

Precise boundary confirmed: HOT (per-packet crypto) `try_decap` (1428–1652, **224**), `encap_inner` (1248–1428, **180**), `inner_ip_len_after_decap` (1718–1780, 62) → `engine/transport.rs`. COLD (peer sync) `reconcile_peers` (853–1005, 152), `install_session` (1117–1198, 81), `classify_initiation` (594–659, 65), `build_initiator_handshake` (1652–1692, 40) → `engine/reconcile.rs`. **Guardrail (dedup §2):** `try_encap`/`encap_inner`/`try_decap` use stack-allocated crypto buffers (no heap), monomorphized (no trait objects), lock-free peer lookup via `RwLock::read`/RCU swap. The split is same-crate so inlining is preserved, but the extraction MUST NOT introduce a `Box<dyn>`/vtable at the module seam and MUST keep the crypto scratch buffers stack-local. Verify with cargo-asm/objdump diff on `try_decap`/`encap_inner` before/after (dedup §2 rule). Class B, not A.

#### [A5-rust-control] event_stream/mod.rs (1693) — STATUS-UPDATE (codex-173-15) + NEW detail — Class B

God-fns confirm sender/worker/io_loop/replay/control/drain split: `handle_drain_request` (1368–1528, 160)→`drain.rs`, `process_control_frames` (1231–1368, 137)→`control.rs`, `run_connected_loop` (1116–1231, 115)+`io_thread_main` (938–991, 53)→`io_loop.rs`, `replay_buffered` (1007–1077, 70)→`replay.rs`, `send_lossless_encoded` (591–674, 83)+`emit_session_close_rt_flow` (761–882, 121)+`emit_session_create_rt_flow` (882–938, 56)→`sender.rs`. Plus a **NEW** cohesion note: the file ALSO owns the clock-anchoring helpers (`mono_ns_to_wall_clock_unix_ns`, `monotonic_ns_to_unix_*`, ~125–324) that belong in a `clock.rs`, AND the RT_FLOW session emitters that overlap conceptually with `codec.rs`/`event_emit.rs`. **Guardrail (Class B, heavy):** the README enumerates the invariants the io_loop/replay/control/drain split must preserve — #3878 seq-alloc-atomic-with-enqueue under `producer_seq_lock`, #2381 16 MiB `write_buf` backlog cap, #2877 nonblocking+stop-aware replay/drain, #2959 ACK-window validation, #2875 poison-on-loss drain fence. These are the fail-on-revert gate; the split is safe only if every one stays pinned. bounded-channel backpressure + io_uring user_data uniqueness (dedup §2) preserved.

#### [A5-rust-control] server/helpers.rs (1292) — INCREMENT(codex-171-10)

`refresh_status` confirmed at **312 LOC** (16–328) — matches the cataloged ~311. **NEW increment detail:** the file is broader than refresh_status alone — it also fuses (a) **queue planning**: `replan_queues` (108), `update_snapshot_binding_plan_key` (84), `replan_bindings_from_candidates` (51), `include_userspace_binding_interface` (42), `reconcile_status_bindings` (41); and (b) **HA session construction**: `build_synced_session_entry` (193), `build_nat64_reverse_rebuild` (37). So the cataloged `server/status/{…}.rs` split should be paired with peeling queue-planning into `server/planning.rs` and HA session-build into `server/session_build.rs`. **Guardrail:** the queue-planning invariant (`replan_queues`/`update_snapshot_binding_plan_key`/`effective_rx_queues` are ONE shared resolution path — #2915/#2916/#3007/#3091, documented at length in `server/README.md`) MUST stay co-resolved; a split that lets the plan-key and the planner read different fields reintroduces the stale-layout / same-plan-skip bug. Keep those three in one `planning.rs`. Cold (control-socket apply/status).

#### [A5-rust-control] Test-file shape (worst colocation in my group)

- `afxdp/coordinator/tests.rs` (**4005**) and `afxdp/wg/tests.rs` (**3909**) are the two largest test files in my group (dedup §1c codex-171-29, OPEN). Both are single monolithic `tests.rs` for a multi-file module — coordinator tests span lifecycle/neighbor/wg-control/tunnel-supervision/cos-lease/status subjects; wg tests span engine/cookie/handshake/session/tai64n/timers. Per engineering-style ">200 tests across unrelated subjects → colocate," these should split next to the production seams (`coordinator/{wg_control,status,tunnel_supervision,cos_leases}` each already have production files that could host a sibling `*_tests.rs`; wg already has `engine_tests.rs` (1464) separate from `tests.rs` (3909), so the pattern is half-done). Note: `wg/engine_tests.rs` exists — the split has STARTED for wg but `tests.rs` is still 3909. Lower priority than the production splits above.

#### [A6-go-config] D-negatives (honest "do not split")

- **types_system.go (1,544) / types_security.go (1,202):** pure typed-config struct
  declarations, 64 types each, biggest struct ~49 LOC (SystemConfig) / ~45 LOC
  (SecurityConfig). No god-struct, no logic, no dumping-ground behavior — subsystems
  cohabit but every type is small and cohesive. A `types_snmp.go`/`types_nat.go` split is
  possible but LOW value (no correctness/reviewability win; churns imports). **D-class.**
- **schema_security.go (1,255) / schema_system.go (1,021) + schema_{interfaces,cos,routing}.go:**
  declarative `var schema… = &schemaNode{ children: {…} }` composite literals — the
  setSchema SSOT. "Big but table-like" (the audit's own honest-D category). Splitting a
  single Go composite literal means fragmenting into sub-`var`s and re-referencing — net
  reviewability wash. Any reshape is gated by the completion/`SchemaValidate` golden tests
  (`schema_validate_test.go`, `schema_complete` tests). **D-class.**
- **parser.go (361):** the lexer/AST core is small and clean (11 fns); there is no
  `parser_*.go` production monolith. The dual-AST + bracket-list contract lives here and
  in `ast_*.go` (all < 830 LOC). **D-negative — nothing to split.**

#### [A7-go-dpmgr] F-A7-11 — retirement_boundary_canary_test.go is a deliberate boundary gate — DO NOT SPLIT

- **Severity**: n/a (honest negative)
- **Confidence**: HIGH
- **Refactor class**: **D (do-not-split)**
- **Dedup tag**: **D-NEGATIVE**
- **Evidence**: `pkg/dataplane/retirement_boundary_canary_test.go` 3,354 LOC, 26 tests. It is a single-purpose #1373-retirement architectural gate: walks the source tree with `go/ast`/`go/parser`, enforces `legacyDataplaneImportAllowlist` (per-file justification map), checks the Makefile and retirement docs, and asserts the `xdp_userspace_prog` entry program. The bulk is the allowlist data + AST-assertion scaffolding — one cohesive invariant enforcer, not a low-cohesion dumping ground.
- **Assessment**: honest negative — this is exactly the kind of large-but-cohesive compile-time invariant the engineering-style doc protects. The allowlist *table* could optionally move to a `testdata` fixture, but the AST-walk logic is one concern and should stay whole. No split warranted.
- **Labels**: do-not-split, canary
- **Dedup note**: D-class; flag so no one re-proposes splitting it by LOC.

#### [A7-go-dpmgr] Notes / non-findings

- `manager.go` (421 LOC) is the clean post-refactor template (dedup §1a FIXED) — cite as the target shape for F-A7-2/3.
- `loader.go` (1,207) — largest fn <110 LOC; its 55 `userspaceShimCompileDataplane` no-op stubs (L349-447) are a single-purpose interface adapter, cohesive. Low-priority A-class (could move to `loader_shim_stub.go`) but not a god-function.
- `dataplane.go` (459) retirement sentinels — D, cohesive.

#### [A8-go-daemon-ha] F13 — D-NEGATIVES (do-not-split; recorded to prevent re-proposal)

- **`device_map.go` (695):** well-factored — both #1956 rename sites (normal boot +
  bootstrap-exit) route through the single `applyStartupNamingPolicy` (L82); the
  dual-branch invariant is CONSOLIDATED, not duplicated. Do not split. Confidence High.
- **`cluster/failover.go` (876):** confirms codex-171-32 D-class — one manual-failover
  `m.mu` lock domain (`ManualFailover`/`RequestPeerFailover` + batch variants + all
  transfer-commit `*Locked` helpers). The "committed-failover-suppresses-stale-
  heartbeat" invariant must stay answerable by reading one file. Keep co-located.
  Confidence High.
- **`bootstrap.go` (931):** SAFE-BOOTSTRAP state machine; `enterBootstrapMode` (123)
  is a cohesive teardown sequence (NAT-alarm stop, .network removal, FRR clear,
  dataplane detach) whose ORDER is the #2114/#1960 contract. No god-fn worth
  splitting; keep. Confidence Medium.
- **`ra/ra.go::Apply` (152):** the draining-tombstone state machine (#2033/#2453/
  #2834/#2865) — splitting the claim-and-hold / make-before-break logic across files
  would fracture the single-owner invariant. Keep. Confidence High.
- **`daemon_ha_userspace.go` / `daemon_ha_fabric.go`:** domain-cohesive; the only
  smell is v4/v6 and fwd0/fwd1 near-duplication (a helper-extraction, not a split).
  Confidence Medium.

#### [A8-go-daemon-ha] Test-file shape (colocation quality)

- **`cluster/sync_test.go` 4,717** — largest test file in group; couples session
  sync, gen-guard, bulk, and dispatch. Prior art: nat/tests.rs was split per module.
  Concrete plan: split alongside the F4 production seam → `sync_conn_dispatch_test.go`,
  `sync_conn_genguard_test.go` (much of `sync_gen_guard_test.go` 956 already lives
  separately — fold the genguard cases there), `sync_bulk_test.go`. **Worst-file
  recommendation: sync_test.go.**
- **`ra/serialize_test.go` 2,648** — wire-serialization tests; already has siblings
  (`sender_marshal_3895/4119/4307_test.go`) colocated by issue. Fold the bulk
  `serialize_test.go` cases toward `sender_test.go` + `buildra_test.go` when F12
  lands. Good colocation discipline already.
- **`vrrp/vrrp_test.go` 2,468** — VRRP already has EXCELLENT test colocation (~20
  `instance_*_test.go` by concern: preempt_gate, preempt_holdtime, master_interval,
  garp_force, rxdrop_race, ifindex_filter, ...). When F3 lands the 6-file seam, the
  residual `vrrp_test.go` cases move to `instance_run_test.go` / `instance_rx_test.go`.
  Low urgency — the colocation is already the project template.

---

#### [A9-go-api-cli] F11 — `cmdtree/tree.go` is a declarative table, NOT a god-function (D-class correction)

- **Severity:** N/A (negative) · **Confidence:** High · **Refactor class:** (D) DO-NOT-SPLIT (mostly)
- **Dedup tag:** D-NEGATIVE(codex-173-21)
- **Evidence:** 1,548 LOC, but `grep -n '^func '` shows small helpers only — `DynamicValues`
  (116→124 = 8 LOC), then nothing until `KeysFromTree`(1141). The ~1,000 LOC gap (124→1141) is the
  `var OperationalTree = map[string]*Node{…}` / config-tree literal — a hand-written declarative
  completion/help table (verified: lines 134+ are nested `{Desc:…, Children:…}` map literals). The
  tail (1141→1548, ~400 LOC) is the real logic: `CompleteFromTree`, `CompleteFromTreeWithDesc`,
  `LookupDesc`, `WriteHelp`, `ResolveUniquePrefix`, `cosClassifierNames`.
- **Assessment:** the cataloged codex-173-21 split
  (`tree_operational/tree_config/completion/help/dynamic_values.go`) is legitimate but LOW value and
  **partly mis-framed**: the bulk is a cohesive declarative table (splitting the `var` across files
  buys little and risks losing the single-SSOT readability the two-SSOT design (#1319) intends).
  The *worthwhile* carve is only the ~400 LOC of completion/help logic into `completion.go`/`help.go`,
  leaving `OperationalTree`/`ConfigTree` as one table file. This is (A) for the tail, (D) for the table.
- **Hot-path preservation:** N/A — completion runs at keystroke cadence, not per-packet.
- **Tests + gate:** `pkg/cmdtree/tree_test.go` + `completion_nil_*_test.go`; `make test-go`.
- **Why it matters:** prevents a low-value "split the big file" churn PR that would fragment the
  declarative SSOT. Record: bulk is D-class; only the completion/help fns are worth a mechanical carve.
- **Fix direction:** if touched, carve `completion.go`/`help.go` off the tail ONLY; keep the tree
  literal whole.
- **Labels:** declarative-table, do-not-split(partial), completion
- **Dedup note:** D-NEGATIVE correction to codex-173-21 — downgrades the split scope.

---

#### [A10-go-services] F-11 — D-NEGATIVE / below-threshold (honest negatives)

- **flowexport/ipfix.go (1,075):** **D for the file** — `ipfixField`/`ipfixHeader`/`IPFIXExporter` are a cohesive protocol template+encoder; largest fn `ExportSessionClose` 66 LOC. Splitting the encoder harms locality of the IPFIX wire contract (template ID ↔ field layout must stay together, cf. codex-158 template-collision fixes). The valid observation is package-level (ipfix.go 1,075 + netflow.go 815 + manager.go 889 = a broad `flowexport` package), STATUS-UPDATE of codex-158's "package too monolithic" note — but no single file warrants a split.
- **ddns/backend_rfc2136.go (1,100):** cohesive RFC2136 TSIG DNS-UPDATE backend; largest fn `sendAddOwned` 100 LOC. One protocol, one responsibility. **D / low** — a size-only flag; the send*/remove* symmetry is intentional. Not worth a split.
- **dhcpserver/dhcpserver.go (1,040):** Kea v4/v6 config-gen + unit lifecycle; `generateKea4Config` 121 + `generateKea6Config` 128 are near-duplicate v4/v6 renderers (a shared `generateKeaConfig(af)` helper is the only real dedup here, small). Below the 1,500 watch tier; **NEW but low** — note the v4/v6 gen duplication, not a monolith.
- **monitoriface/monitor.go (952):** `RenderSingleInterface` (:552) 178 LOC is a terse+detail interface-stat renderer — a presentation god-fn (split into `renderTerse`/`renderDetail`/`renderCounters`), but the file is below threshold and the render is cohesive. **NEW but low.**
- **frr/manager.go (911), ipsec/ike.go (890), routing/vrf.go (361):** below/at threshold, cohesive; no action.


### 6.4 Status corrections to the prior catalog (22)

#### [A1-rust-hotpath] F2 — `poll_stages.rs` is 972 prod / 2,555 test; the cataloged 6-way production split is over-scoped

- **Title:** `poll_stages.rs` REFACTOR-tier heatmap number (3,527) is 72% inline tests; production is only 972 LOC of already-cohesive stage fns — the codex-171-3 `{l2_learn,gre,flow_parse,fabric,screen,ipsec}.rs` split is unnecessary; the actionable lever is the test move + the one oversized `stage_screen_check`.
- **Severity:** LOW-MED (catalog-correction; avoids a low-value 6-way churn on hot stage fns).
- **Confidence:** HIGH (test block 973–3527 measured; all 9 prod fns enumerated with line boundaries; no prod code after 973).
- **Refactor class:** (A) MECHANICAL for the test move; (D) DO-NOT-SPLIT for the 6-way production carve (stages are small, cohesive, and hot).
- **Dedup tag:** STATUS-UPDATE(codex-171-3 / agy-171-03 / codex-173-13).
- **Evidence:**
  ```
  73   stage_link_layer_classify        (166 LOC)
  240  stage_native_gre_decap           (27)
  268  stage_parse_flow_and_learn       (37)
  306  stage_classify_fabric_ingress    (27)
  390  stage_screen_check               (316 LOC)   <- only real god-fn cue
  707  stage_screen_syn_cookie_ack_on_session_miss (135)
  901  stage_ipsec_passthrough_check    (71)
  973  #[cfg(test)] mod tests { … }      (2,555 LOC, 26 tests)
  ```
- **Proposed decomposition:**
  - Move `mod tests` (973–3527) to `poll_stages/tests.rs` (the #1034/#1046 colocation pattern). Drops the file to ~972 LOC — **off the REFACTOR heatmap entirely**. This is the whole win.
  - Optionally split *only* `stage_screen_check` (390–706, 316 LOC): it fuses flow-present vs flowless-branch screen dispatch (#3064/#3902/#4155 layered in). Extract the flowless arm (`check_flowless_screens_opts` caller) into `stage_screen_check_flowless` — but this is same-file, `#[inline]`, and marginal. Do NOT carve the other 8 stages.
- **Hot-path preservation analysis:** stages are called per-descriptor on every non-cache-hit; they must stay same-crate `#[inline]`-eligible. Moving *tests* is inert to codegen. If `stage_screen_check` is ever split, both arms stay `#[inline]` and the flowless arm is `#[cold]` (it is the rarer non-first-fragment / non-query-ICMP path). The `size_of::<UserspaceDpMeta>()` uses at 1024/1115/1650/2626 are all in the test block — no layout pin moves with production.
- **Tests + gate:** the 26 tests move verbatim into `poll_stages/tests.rs`; `make test-rust` proves the move is behavior-preserving. `stage_screen_check` behavior is pinned by the screen tests already in this block (LAND/teardrop/ping-of-death/flood/syn-cookie).
- **Why it matters:** the catalog's directional heatmap makes `poll_stages.rs` look like the #2 Rust monolith; it is not. Spending a 6-PR stream carving 972 LOC of hot stage fns into 6 files adds call-boundary/review churn for near-zero modularity gain and some inlining risk. The honest fix is a one-PR test relocation.
- **Fix direction:** one PR: relocate inline tests → `poll_stages/tests.rs`. File clears the threshold; revisit `stage_screen_check` only if it grows past ~400 LOC.
- **Labels:** refactor, test-colocation, rust-dataplane, catalog-correction, codex-171-3.
- **Dedup note:** codex-171-3 is OPEN and lists both the 6-way split AND "move mod tests (~2K)". This sharpens: the test block is 2,555 LOC (72%), prod is 972, so the 6-way split should be **downgraded to D** and only the test move + optional `stage_screen_check` split retained.

#### [A2-rust-fwd-frame] F1 — `DEFAULT_V4_TABLE.to_string()` per-forwarding-resolution heap alloc (still present)

**Title:** `forwarding/mod.rs` allocates a `String` for the default route
table on every FIB resolution (session-miss + fabric cache-validate).
**Severity:** Low (perf) · **Confidence:** High
**Refactor class:** (B) requires guardrails (cargo-asm/objdump + a perf smoke)
**Dedup tag:** STATUS-UPDATE (dedup §2 "PERF BUG noted: `DEFAULT_V4_TABLE.to_string()`")

**Evidence** (`forwarding/mod.rs:1456-1544`):
```rust
IpAddr::V4(ip) => {
    let table = table
        .map(|table| canonical_route_table(table, false))
        .unwrap_or_else(|| DEFAULT_V4_TABLE.to_string());   // ← heap alloc every call
    ...
    lookup_forwarding_resolution_v4(state, dynamic_neighbors, ip, &table, 0, true, ecmp_flow_hash)
}
```
`canonical_route_table` (line 48) **always** returns an owned `String` (even the
no-rewrite arms `return table.to_string()`), so the `Some(table)` branch also
allocates. `DEFAULT_V4_TABLE`/`DEFAULT_V6_TABLE` are already `&'static str`
(lines 12-13) — the alloc is purely to satisfy the `String` return type.

**Hotness correction to the catalog:** the catalog calls this "per-packet". It
is actually **per forwarding-RESOLUTION** — reached from
`lookup_forwarding_resolution_inner_ecmp` via `_with_dynamic` /
`_with_dynamic_for_flow`, i.e. every **session-miss** (new flow) and every
fabric-ingress `cached_flow_decision_valid` / `prefer_local_forward_candidate`
re-resolution. Established flows hit `flow_cache_hit.rs` and do NOT reach here.
Still a real alloc on the new-flow path, not line-rate-per-established-packet.

**Proposed fix:** change `canonical_route_table` to return
`Cow<'a, str>` (borrow the input in the no-rewrite arms, `Cow::Owned` only for
the `<inst>.inetX.0` rewrite), and the default arms to
`Cow::Borrowed(DEFAULT_V4_TABLE)`. `lookup_forwarding_resolution_v4(.., &table,
..)` already takes `&str`, so `&*table` (Cow deref) is a drop-in. Zero alloc on
the default-VRF path; alloc survives only for genuine `<vrf>.inet.0` rewrites.

**Hot-path preservation analysis:** no signature change to the inner FIB
functions (they take `&str`). Verify the deref does not defeat inlining of
`lookup_forwarding_resolution_v4_inner` via `cargo asm`; confirm no alloc on the
default path with a `dhat`/`heaptrack` new-flow microbench. The `visited:
Vec<String>` + `visited.push(table.to_string())` next-table alloc (lines
2010/2137/2345) is **separate** and only fires on PBR/rib-group next-table
recursion (rare) — leave it or switch to `SmallVec<[Cow;8]>` in the same PR.

**Tests + gate:** existing `forwarding/tests.rs` route-lookup cases cover
correctness; add a `dhat` allocation-count assertion for a default-VRF
session-miss. Gate: `make test-rust`.

**Why it matters:** one `String` alloc+free per new flow under connection churn
(SYN flood, short-lived HTTP) is allocator pressure the hot path shouldn't pay;
`docs/engineering-style.md` "Never allocate per packet."

**Fix direction:** `canonical_route_table -> Cow<'static/'a, str>`.
**Labels:** perf, hot-path, allocation. **Dedup note:** confirms the §2 bug is
UNFIXED at HEAD; refines its hotness from "per-packet" to "per-resolution".

---

#### [A2-rust-fwd-frame] F8 — `frame/tcp_segmentation.rs` cataloged dead branch is ALREADY REMOVED (#4384)

**Title:** The cataloged dead+wrong incremental-checksum branch
(dedup §1d, opus-171 L-3, "266-322") no longer exists.
**Severity:** Informational · **Confidence:** High
**Refactor class:** — · **Dedup tag:** STATUS-UPDATE (close dedup §1d item)

**Evidence** (`frame/tcp_segmentation.rs:241-255`): the branch was deleted by
#4384; the code now unconditionally recomputes the L4 checksum in BOTH arms:
```rust
// A per-segment incremental adjustment ... is never valid (#4384): each
// segment carries a different payload chunk, a rewritten seq, a cleared PSH ...
// The removed incremental branch was gated on `enforced_ports.is_none()`,
// which is unreachable ... so it was dead-but-wrong ...
recompute_l4_checksum_ipv4(packet, ip_header_len, meta.protocol, false)?;   // v4 arm
...
recompute_l4_checksum_ipv6(packet, ip_header_len, meta.protocol)?;          // v6 arm
```
The team-lead brief asked to "verify and fold into a finding if a split would
make it live" — there is nothing to make live; the always-recompute is now the
only path. The "common fabric case" comment the catalog flagged is gone.

**Hot-path preservation analysis:** the always-recompute is the correct hot-path
behavior (full L4 checksum over pseudo-header + segment bytes); no landmine
remains for a future split.

**Why it matters:** removes a latent-High from the dead-code backlog; no action.

**Fix direction:** none — mark dedup §1d `tcp_segmentation.rs:266-322` FIXED.
**Labels:** status-update. **Dedup note:** close opus-171 L-3.

---

#### [A4-rust-session-policy] F3 — policy_snapshot_error.rs: extraction clean; keep single enum, do NOT sub-type

- **Severity:** Low · **Confidence:** High · **Refactor class:** D · **Dedup tag:** STATUS-UPDATE(#4421 inc 1)
- **Evidence:** 896 LOC = one `pub(crate) enum SnapshotIntegrityError` (11–627, **19 variants**) + `Display::fmt` (628–895, ~267 LOC) + empty `Error` impl. Variants span domains: address-book (AddressBookIdZero, UnrepresentableAddressBookPrefix), application (InvalidApplicationIcmpFields), nat64 (Nptv6OverlappingPrefix), filter (UnrepresentableFilterProtocol/TCPFlags/ICMP/DSCP/FlexMatch, FilterDSCPOutOfRange, UnsatisfiableFilterCrossField, MissingFilterRef), cos (SchedulerMapUnknownClass, CosUnknownEqualFlowTargetPolicy, CosUnknownSchedulerPriority), route (RouteFamilyMismatch, RoutePreferenceOutOfRange), neighbor (NeighborFamilyMismatch), zone (DuplicateZoneId). The former `Nat64UnparseableRule` variant was removed (comment at 163).
- **Proposed decomposition:** NONE. This is the single fail-closed error type threaded through `build_forwarding_state_*` → `build_reconcile_forwarding` preflight; a flat enum is exactly what a single `?`-propagating result type wants. Sub-typing per domain (nesting `FilterIntegrityError` etc.) would add wrapper conversions on a cold path and split the one match arm every reconcile caller relies on. The 267-LOC `Display` is a mechanical per-variant message block — cohesive with the enum.
- **Hot-path preservation:** N/A (cold reconcile).
- **Why it matters:** confirms #4421 inc-1 landed clean and answers the audit's open question ("dumping ground worth sub-typing?") — **no**.
- **Fix direction:** leave as-is. If it grows past ~1,200, split `Display` into `policy_snapshot_error/display.rs` only (mechanical), never the variant set.
- **Labels:** modularity-negative. **Dedup note:** closes the A4-briefed question.

#### [A4-rust-session-policy] F5 — session/lookup.rs: hot-path `metadata.clone()` refcount churn persists

- **Severity:** Medium (perf) · **Confidence:** High · **Refactor class:** C · **Dedup tag:** STATUS-UPDATE (known bug)
- **Evidence:** `entry.metadata.clone()` at `lookup.rs:183, 240, 281, 321` — the forward-NAT-match, forward-wire-match, primary `lookup`, and single-entry read paths. `SessionMetadata` carries `Option<Arc<PolicyRuleCounter>>` (policy_counter) + `Option<Arc<…>>` fields, so each clone is `LOCK XADD` atomic refcount bumps on the per-packet read path. `update_session` (mod.rs:1265) also clones. This is the exact cataloged hit-path bug — still live at HEAD.
- **Proposed decomposition:** not a split — a **return-shape** fix carried WITH the session refactor: have the lookup family return `SessionLookup { handle: u32, decision, origin }` (indices, `Copy`) and resolve metadata by handle at the ≤1 site that truly needs owned metadata, instead of cloning into every `SessionLookup`. Where callers only read scalar fields (timeouts, flags), expose accessor methods on `&SessionEntry` rather than a cloned `SessionMetadata`.
- **Hot-path preservation:** removing the clone REMOVES atomics — strictly positive. Guard: any new accessor must be `#[inline]`; do not replace the Arc clone with a borrow that extends the `entries` borrow across a `push_to_wheel` (`lookup_with_origin` drops the borrow before wheel push — preserve that ordering).
- **Tests + gate:** `session/tests.rs` lookup/NAT-reverse clusters; a criterion micro-bench over `lookup` on an established flow to show the atomics gone; `make test-failover`.
- **Why it matters:** this fires on ~every packet that misses the flow-cache and re-runs lookup; it is the single highest-value item in the session module.
- **Fix direction:** file/attach to the session #4421 increment; do the return-shape change in the same PR as the F4 split so the seam is touched once.
- **Labels:** hot-path, perf-bug. **Dedup note:** the catalog's "hit-path metadata.clone()" — confirmed at 4 lookup sites + 2 in mod/shared_ops.

#### [A4-rust-session-policy] F8 — nat/allocator.rs: GC-under-Mutex confirmed; alloc god-fn already peeled

- **Severity:** Medium (lock contention, latent) · **Confidence:** High · **Refactor class:** C · **Dedup tag:** STATUS-UPDATE(#4409)
- **Evidence:** `allocate_translation` (405–529 = **124 LOC**, down from cataloged 148 after #4409 inc-1 peeled `reuse_existing_lease_locked`(553)). The contention pattern is intact: line 429–430 takes `self.shared.live.lock()` then immediately runs `self.gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET)` inside the hot alloc under the shared `Mutex`; further budgeted GC at 469/483. GC is **budgeted** (`ALLOCATION_GC_BUDGET`/`PRESSURE_GC_BUDGET`) rather than a full BTreeSet sweep, which softens but does not remove the "GC runs under the alloc lock" issue. `PortAllocatorShared` (Mutex-held `live`) vs `PortAllocatorLiveState` split already exists.
- **Proposed decomposition:** cataloged `pool_gc.rs`/`pool_lease.rs`/`pool_status.rs` + rename to `nat/pool.rs`. Move `gc_expired_locked`/`gc_expired_for_addr_locked`/`release_expired_lease_locked` to `pool_gc.rs` and mark them `#[cold]`; keep `claim_free_port_locked`/`assign_owner_locked` in the hot `pool.rs`.
- **Hot-path preservation:** the real win is **narrowing the lock** — the perf backlog note is "split hot/cold, `#[cold]` GC, minimize lock hold." A pure code-motion split does NOT fix contention by itself; pair it with moving the GC sweep off the alloc critical section (e.g. amortized GC on a separate cadence) — but that is a behavior change, so file it as its own issue (scope discipline), do not ride it in the split PR.
- **Tests + gate:** `nat/tests_pool.rs` / `tests_scope.rs` (already split); a criterion bench on `allocate_translation` under a full-table workload; `make test-failover`.
- **Why it matters:** blocks ~every new-flow SNAT alloc behind a shared mutex that also does GC.
- **Fix direction:** `#[cold]` the GC fns + `pool.rs` rename now; open a separate issue for lock-narrowing (behavior).
- **Labels:** modularity + lock-contention. **Dedup note:** updates #4409 status (alloc fn 148→124; inc-1 landed).

#### [A4-rust-session-policy] F13 — slowpath.rs: seam validated; WATCH tier is test-inflated; io_uring invariants intact

- **Severity:** Low · **Confidence:** High · **Refactor class:** B · **Dedup tag:** STATUS-UPDATE(codex-173-16)
- **Evidence:** 1,659 LOC but **production is only ~73–918 (~845 LOC)**; lines ~919–1659 (~740) are one inline `mod tests`. The cataloged {reinjector,worker,write_sync,write_uring,tun_setup,sysctl} seam maps to: reinjector+status+rate-limiter (73–400), `slow_path_worker`(401), write_sync (`write_packet_sync/atomic/nonblocking`, 461–628), write_uring (`write_packet_io_uring*`, 630–683), tun/sysctl (`open_tun`/`rp_filter`/`set_if_*`/`set_ipv4_sysctl`/`IfReq`, 685–918). **io_uring invariants CONFIRMED intact:** `write_packet_io_uring` (630) delegates to `io_uring_write::write_all_to_fd` which "matches the completion by user_data so a stale CQE cannot corrupt the offset, and returns only after the matching CQE is reaped so `bytes` outlives every kernel reference (#2297)"; the `safe_to_retry` partial-write guard (#2477) is already factored into a **unit-testable** `decide_sync_fallback` (668).
- **Proposed decomposition:** cataloged split IS valid, but note the priority is really a **test-split** (740 LOC of inline tests) — production at ~845 is below the 2,000 line. Split `slowpath/tun_setup.rs` (open_tun/set_if_*/sysctl/IfReq) + `slowpath/write.rs` (sync+uring+decide_sync_fallback) + keep reinjector/worker in `mod.rs`.
- **Hot-path preservation:** slow path (TUN reinject), not per-packet fast path. The only hard invariant is the io_uring user_data uniqueness + stale-CQE guard — those live in `crate::io_uring_write`, not slowpath.rs, so the split cannot break them. Keep `decide_sync_fallback`'s "partial/ambiguous → drop, never re-send" contract (it prevents truncated+duplicate TUN frames).
- **Tests + gate:** the inline tests (rate-limiter/sync/nonblocking/uring-fallback) move next to their fns; `make test-rust`.
- **Why it matters:** the WATCH flag overstates the production monolith; the real modularity work here is colocating ~740 LOC of tests.
- **Fix direction:** split tests first, then the production 3-way; low urgency.
- **Labels:** modularity, test-split. **Dedup note:** corrects the effective production LOC (845, not 1,659) and confirms io_uring guards.

#### [A4-rust-session-policy] F16 — filter/engine + policer: well-decomposed; SmallVec cap smell is FIXED (#4566)

- **Severity:** Low · **Confidence:** High · **Refactor class:** D · **Dedup tag:** STATUS-UPDATE / D-correction (catalog 1d)
- **Evidence:** `filter/engine/` is already split into `eval.rs`(1,026, all `#[inline]`), `matching.rs`(376, the `#[inline(always)]` primitives), `cache_sensitive.rs`(586), `tx_selection.rs`(419), `policer.rs`(57), `mod.rs`(38) — a clean template split. `filter/policer.rs` (~485, srTCM/trTCM core) is small and cohesive. **The cataloged "CachedThreeColorPolicers hard-caps at 2, 3rd+ silently never meters (#4566)" is RESOLVED:** `filter/mod.rs:465` now `policers: SmallVec<[Arc<ThreeColorPolicerRuntime>; 2]>` (inline cap 2, spills to heap for ≥3 off the hot path); the README documents #4566 chose "grow the array" so cached and live paths meter identically for all counts. The finding location was also wrong in 1d (it's `filter/mod.rs`/`engine`, not `policer.rs`).
- **Proposed decomposition:** NONE for engine/policer. `eval.rs` at 1,026 is the only WATCH-adjacent piece; its functions are all `#[inline]` first-match evaluators tightly bound to `matching.rs` — a further split risks the inlining the perf note pins (`evaluate_filter_ref_counted_v4/v6`, `term_matches_v4/v6`). Leave.
- **Hot-path preservation:** confirms the `#[inline(always)]` primitives in `matching.rs` and the per-packet SmallVec built-once/read-only invariant (no hot-path alloc — the spill happens at flow-cache install).
- **Tests + gate:** existing.
- **Why it matters:** removes a stale open item from the backlog (SmallVec cap) and confirms the filter engine needs no split.
- **Fix direction:** update catalog 1d to mark #4566 fixed; leave engine as-is.
- **Labels:** modularity-negative, dead-finding-cleanup. **Dedup note:** **CORRECTION** — catalog 1d/#4566 SmallVec cap is fixed at HEAD; wrong file attributed.

#### [A5-rust-control] wg_control.rs (2280) — STATUS-UPDATE (codex-173-17), no increment

God-fns confirm the proposed loop/attempt/socket/cmsg/inbound/tun/keepalive split precisely:
`run_wg_control_loop` (332–653, **321**), `dispatch_inbound` (1307–1523, **216**), `drive_attempt_machine` (698–832, 134), `wg_control_loop` (121–225, 104), `set_recv_tos_options` (1038–1127, 89, cmsg/socket), `encap_and_send` (1523–1585, 62, tun), `bind_dual_stack_v6` (927–989, 62, socket). **Class A** — this is the WG *control* thread (handshake init, keepalive pacing, inbound-handshake dispatch, recv-ToS cmsg), NOT the per-packet encap/decap (that is `wg/engine.rs`). Cold path; safe to split. Map: `run_wg_control_loop`→`loop.rs`, `drive_attempt_machine`→`attempt.rs`, `dispatch_inbound`→`inbound.rs`, `set_recv_tos_options`+`bind_dual_stack_v6`→`socket.rs`, `encap_and_send`→`tun.rs`. #1 REFACTOR-tier file in my group (>2000).

#### [A5-rust-control] wg/cookie.rs (1435) — STATUS-UPDATE (codex-171-18), no increment

No god-function — largest prod fns are modest: `macs_equal` 90, `build_cookie_reply` 60, `secrets` 58, `source_reply_allowed` 58, `new` 49, `reply_budget_available` 37. The 1435 LOC is spread across responder / rate-limit (source-table cap, token budget) / initiator, PLUS a large inline test block (`initiator_cookie_roundtrip…` 46, `getrandom_failure_fails_closed…` 43, `source_table_cap_fails_closed` 38, …). The biggest lever in the cataloged `cookie/{mod,responder,rate_limit,initiator,tests}.rs` split is **moving the inline tests to `cookie/tests.rs`**; the production split is low-value (WATCH-tier, 1435<2000, cohesive crypto). Cold path (cookie replies only under DoS/load). Class A. `getrandom` fail-closed (no weak secret) invariant must stay pinned.

#### [A5-rust-control] afxdp/event_emit.rs (1492) — STATUS-UPDATE (codex-173-12), no increment

Well-factored already: `emit_policy_deny_event` 92, `emit_filter_log_event` 58, `emit_screen_drop_event` 54, `emit_screen_alarm_event` 52, `emit_host_inbound_deny_event` 49 — one clean fn per event kind. The cataloged `event_emit/{policy,host_inbound,screen,filter,wire}.rs` split is a low-value one-file-per-emitter mechanical move; the bigger lever is **moving the large inline test block** (`cold_path_events_carry_resolved_app_id` 67, `policy_deny_event_dnat_logs_post_translation…` 64, `emitted_timestamps_are_non_decreasing` 56, …) to `event_emit/tests.rs`. Cold path (per deny/drop/log/session-event, not per-packet). Class A. Preserve `resolve_flow_app_id` directional lookup (#3321) and the wall-clock-per-emit stamping (#2470) — these must stay shared, not forked per emitter file.

#### [A5-rust-control] afxdp/coordinator/cos_leases.rs (838) — STATUS-UPDATE (adjacent #4408)

Not primary, but noting: `aggregate_cos_statuses_across_workers` (169–388, **219**) and `build_shared_cos_queue_leases_reusing_existing` (113) are large. CoS lease refresh runs on reconcile/status (cold), but the underlying `shared_cos_lease`/`FlowFairState` storage is a D-class perf layout (dedup §1f). The 219-LOC aggregator is a legitimate extraction target (per-worker fold → helper) but sits under the #4408 cos umbrella; flag for that issue rather than a new one.

---

#### [A6-go-config] STATUS-UPDATES (cataloged items now resolved/advanced)

- **schema_validators.go: codex-173-1 DONE** — was 1,159 LOC, now 186 + 9 domain siblings
  (`schema_validators_{cos,ddns,devicemap,ipsec,logging,network,routing,scheduler,system}.go`,
  largest _cos at 293 LOC). Split landed; close codex-173-1.
- **compiler_security.go: fable-163 F28 / codex-131 L01 DONE** — was ~2,357 LOC grab-bag,
  now 96 LOC dispatch + `compiler_security_{addressbook,alg,flow,log,policy,screen,zones}.go`
  (largest _flow at 728). Grab-bag dissolved.
- **compiler.go compileExpanded: agy-171-09 effectively DONE at fn level** — 2,435 → 124 LOC
  orchestrator (see F3); residual file mass is the compileOpts struct, not the function.
- **compiler_validate_strict.go: ps-011 DONE (confirmed)** — 15-file layout intact; the two
  largest residuals `compiler_validate_strict_filter.go` (1,660, 28 small validators) and
  `compiler_validate_strict_policy.go` (1,009, 17 validators) are the *products* of the
  split, not new monoliths — no god-fn inside (largest 142/137 LOC). If `_filter` grows,
  it sub-splits cleanly (port/address/protocol/dscp/routing-instance clusters), but it is
  NOT a finding today.

#### [A7-go-dpmgr] F-A7-4 — opus-172 H-4 dead-counter indices are now PARTIALLY fixed (dedup correction)

- **Severity**: LOW (observability)
- **Confidence**: HIGH
- **Refactor class**: n/a (dead-code status correction)
- **Dedup tag**: **STATUS-UPDATE (opus-172 H-4 / dedup §1d)**
- **Evidence**: dedup §1d claims `GlobalCtrDrops`(2) + `GlobalCtrNATAllocFail`(7) "never written". As of **#4477** they ARE bridged — `manager_ha.go` `syncBPFCountersLocked` L779-780:
  ```go
  {dataplane.GlobalCtrDrops, safeDelta(cur.totalDrops(), prev.totalDrops())},
  {dataplane.GlobalCtrNATAllocFail, safeDelta(cur.natAllocFail, prev.natAllocFail)},
  ```
  Still genuinely dead (write-side): `GlobalCtrTCEgressPackets`(9) — retired TC path #1476 — and `GlobalCtrFabricRedirect`(26): `grep` across `pkg/dataplane` shows both only in the `types.go` const block, never incremented.
- **Why it matters**: re-filing GlobalCtrDrops/NATAllocFail as an observability lie would be a finding-quality miss — they now surface live deltas. The residual dead pair (9, 26) is retired/unbridged; index 9 is expected-dead (retired path) and index 26 is a real gap if fabric-redirect volume is meant to be visible.
- **Fix direction**: for #4421/#4422 follow-up — either bridge `GlobalCtrFabricRedirect`(26) from a binding counter or delete the index; drop `GlobalCtrTCEgressPackets`(9) as retired.
- **Labels**: dead-code, observability, status-update
- **Dedup note**: corrects dedup §1d bullet 4.

#### [A7-go-dpmgr] F-A7-6 — protocol.go split is pure A-class (validate the 6-file seam; no builder fusion)

- **Severity**: LOW (review-cost; top WATCH by size)
- **Confidence**: HIGH
- **Refactor class**: **A (mechanical)**
- **Dedup tag**: **STATUS-UPDATE (codex-171-11)**
- **Evidence**: `pkg/dataplane/userspace/protocol.go` 2,979 LOC = **77 `type … struct` + exactly 2 methods** (`ProcessStatus.MarshalJSON` L1796, `UnmarshalJSON` L1812). No builders, no compile logic — confirmed **no struct-vs-builder fusion**. Natural clusters map to the cataloged seam:
  - `protocol/snapshot.go`: ConfigSnapshot, Zone/Interface/Address/Route/Neighbor + CoS* (L54-473)
  - `protocol/nat.go`: SourceNAT/StaticNAT/DestinationNAT/NAT64/Nptv6 rule snapshots (L503-841)
  - `protocol/security.go`: Screen/FirewallFilter/FirewallTerm/FlexMatch/Policer/Policy* (L842-1249)
  - `protocol/status.go`: ProcessStatus + Wg/CoS/Binding/Queue/Flow status (L1322-2732) — **carries the 2 methods**
  - `protocol/control.go`: ControlRequest/Response, Forwarding/Queue/Binding control, Inject (L29-53, 2317-2771)
  - `protocol/ha.go`: HAStateUpdateRequest, HAGroupStatus, SessionSync/Delta (L2098-2879)
- **Hot-path preservation**: none — DTOs. All in package `userspace`; moving a struct between files in the same package is **zero-risk** (JSON wire tags travel with the field). The only gate is the wire golden test (`protocol_test.go`, 1,914 LOC — the `protocol_wire_v1.json`-style parity assertion referenced by the lead was not found as a standalone testdata file; the parity lives in `protocol_test.go` / `protocol_failopen_2124_test.go`).
- **Snapshot-decode boundary**: the Go `build*Snapshot` functions that populate these structs (in process.go/policies.go/nat.go/zones.go — see F-A7-8) must keep mirroring Rust `validated.rs` u16/u8 ceilings; the DTO split does not touch those builders, so the invariant is untouched.
- **Tests + gate**: `protocol_test.go`, `protocol_failopen_2124_test.go`, `snapshot_allowlist_test.go`; `make test-go`.
- **Why it matters**: top WATCH by LOC but lowest-risk split in the group — good first move.
- **Labels**: refactor, class-A, wire-mirror
- **Dedup note**: cataloged; validated no builder fusion + concrete line ranges.

#### [A7-go-dpmgr] F-A7-7 — eventstream.go split validated (transport/dispatch/pending/decode/counters)

- **Severity**: LOW
- **Confidence**: HIGH
- **Refactor class**: **B (guardrails)** — goroutine loops + ack/seq ordering
- **Dedup tag**: **STATUS-UPDATE (codex-171-13)**
- **Evidence**: `pkg/dataplane/userspace/eventstream.go` 1,169 LOC (catalog 1,155; grew), 40 fns. Seam confirmed live: transport = `acceptLoop`(271)/`readLoop`(328-488)/`writeFrame`(794)/`ackLoop`(763); dispatch = `dispatchOrQueueSessionFrame`/`…FullResync`/`…Dataplane` (549-629); pending ring = `enqueue/flush/clearPendingCallbackFrames` (635-725); decode = `decodeSessionEvent`(883)/`decodeSessionCloseEvent`(1021)/`decodeDataplaneEventPayload`(1084)/`formatIP`/`formatMAC`; counters = `recordDataplaneEvent`/`recordDataplaneEventDrop` (725-763).
- **Hot-path preservation**: telemetry path — `handleSessionSyncGap`/`markFrameApplied` seq-continuity and ack coalescing must stay with the transport loop; decode fns are pure (safe to move). No control-socket coupling (own unix socket).
- **Tests + gate**: `eventstream_test.go` (2,412); `make test-go`.
- **Labels**: refactor, class-B
- **Dedup note**: cataloged; seam still valid at HEAD.

#### [A7-go-dpmgr] F-A7-8 — per-domain snapshot builders remain unsplit (codex-173-3..7 status)

- **Severity**: LOW
- **Confidence**: MEDIUM
- **Refactor class**: **B (guardrails)** — these are the u16/u8 snapshot-decode boundary
- **Dedup tag**: **STATUS-UPDATE (codex-173-3..7)**
- **Evidence**: the per-domain `build*Snapshot` files are still discrete and mostly <650 LOC at HEAD: `filters.go`(609), `interfaces.go`(561), `nat_destination.go`(520), `nat_source.go`(502), `policies_addrbook.go`(489), `zones_host_inbound.go`(394), `process.go`(270). None is individually a monolith; the codex-173 per-domain split is largely already realized (they are separate files, not one dumping-ground). manager_test.go's 68 `Build*` tests exercise them.
- **Hot-path preservation**: these builders enforce the Rust `validated.rs` u16/u8 ceilings (zone-count cap #2410, VlanId/QueueId/TunnelTtl) — a single oversized Go `int` kills snapshot decode. Any future consolidation must keep the range clamps at the builder.
- **Fix direction**: NO ACTION — already decomposed per-domain; treat codex-173-3..7 as effectively satisfied except where a single file later crosses ~800 LOC.
- **Labels**: status-update, snapshot-boundary
- **Dedup note**: downgrades codex-173-3..7 — the feared monolith did not materialize.

#### [A8-go-daemon-ha] F4 — `cluster/sync_conn.go` STATUS-UPDATE (1,858, grew ~1,515→1,858) + new seam

- **Title:** `sync_conn.go` grew past the prior-campaign snapshot; `handleMessage`
  is a 346-LOC / ~27-case dispatcher and the generation-guard is a separable submodule.
- **Severity:** Medium.
- **Confidence:** High.
- **Refactor class:** (D-leaning B) — the generation-guard state machine is
  DO-NOT-CASUALLY-SPLIT (ordering-critical), but the message dispatch and the
  genguard *helpers* can move to sibling files without touching the state machine.
- **Dedup tag:** STATUS-UPDATE (prior campaign flagged ~1,515–1,589; committed
  heatmap still says 1,515; current 1,858).
- **Evidence:** `handleMessage` L1371–1717 (346 LOC) switches 27 `syncMsg*` types
  (session v4/v6, delete v4/v6, bulk start/end/ack, heartbeat/ack, config, ipsecSA,
  dhcpLease v4/v6, failover ×8, fence, clockSync, prepareActivation, barrier/ack).
  49 `SessionSync` methods in one file. Generation-guard cluster: `nextInstallGen`,
  `takeDeleteGenV4/V6`, `recvGenV4/V6` tombstone, `GenMapOverflow`, `resetRecvGen`
  (#2170/#2221/#2198).
- **Proposed decomposition (NEW detail only):** (1) split the dispatch by concern —
  `sync_conn_dispatch.go` keeps the `handleMessage` switch as a thin router to
  `handleSession* / handleBulk* / handleFailover* / handleLeaseIPsec*` groups
  (the failover ×8 cases alone are ~90 LOC of the 346); (2) move the
  generation-guard helpers (`nextInstallGen`/`takeDeleteGen*`/`recvGen` accessors)
  to `sync_conn_genguard.go` — they are a cohesive, independently-testable unit
  already fronted by their own doc comments.
- **Hot-path preservation analysis:** Session sync is control-path, not per-packet,
  but it is the failover-survival path. Preserve: (1) the per-peer receive path is
  single-threaded over one active fabric (#2198 F3) — the check→Put→record apply
  sequence is deliberately NOT under one `recvGenMu`; a split must not "helpfully"
  add a lock; (2) the delete-tombstone / install-guard ordering (`deleteClusterSynced*`
  refuses strictly-older, install refuses regression) is behavior — keep the compare
  logic intact; (3) `writeFull` is the single seal chokepoint under `s.writeMu`
  (F23 auth) — do not fork writers; (4) the incremental sweep's `Created >= threshold`
  narrowing (#270, NOT LastSeen) must not be "restored" during any refactor.
- **Tests + gate:** `sync_test.go` (4,717), `sync_gen_guard_test.go` (956),
  `sync_config_gen_test.go`; `make test-go`; behavioral `make test-failover` +
  `make test-ha-crash` (session-sync continuity across failover).
- **Why it matters:** The dispatch is the widest single decision in cluster HA and
  keeps accreting message types (dhcp-lease, ipsec-sa, batch failover all landed
  post-split); every new wire type widens the 346-LOC switch.
- **Fix direction:** genguard extraction first (self-contained, well-doc'd), then
  the dispatch-by-group router. Do NOT touch the tombstone/generation compare
  semantics in the same PR (scope discipline).
- **Labels:** refactor, pkg/cluster, sync, monolith.
- **Dedup note:** Prior campaign flagged the state machine at ~1,589; this adds the
  updated LOC (1,858), the concrete 27-case dispatch measurement, and the
  genguard-submodule + dispatch-router seam (new vs the prior "state machine is big"
  note).

#### [A9-go-api-cli] F2 — metrics_userspace.go is already fn-decomposed; carve is file-only, single-`Status()` holds

- **Severity:** Low · **Confidence:** High · **Refactor class:** (A) MECHANICAL
- **Dedup tag:** STATUS-UPDATE(codex-171-16)
- **Evidence:** 1,819 LOC but `grep -n '^func '` shows 1 dispatcher + ~40 `emit*(ch, status)`
  emitters. `collectUserspaceStatus` (line 18) fetches status ONCE and threads the same
  `status dpuserspace.ProcessStatus` into every emitter — the control-socket-contention
  invariant (dedup-summary §2 / hot-path §2) is intact; no emitter re-fetches.
- **Proposed decomposition:** the codex-171-16 split
  (`metrics_userspace_{cos,fairness,sessions_nat,wireguard,fabric_reject,worker}.go`) is a pure
  file move of the existing emitter fns — no fn surgery needed.
- **Hot-path preservation:** `collectUserspaceStatus` IS the scrape path. **HARD CONSTRAINT:
  the carve must not add a second `dp.Status()` / control-socket round-trip** — keep the single
  fetch in the dispatcher and pass `status` down. Any carve that gives an emitter its own fetch
  regresses #-control-socket contention.
- **Tests + gate:** metrics_userspace_*_test.go set + `make test-go`. Add/keep an assertion that
  the scrape issues exactly one `Status()` (a fake DP counting calls).
- **Why it matters:** low — it's already modular by function. Included only to record that the
  cataloged item is lower-value than its LOC implies and carries a preservation constraint.
- **Fix direction:** bundle with F1. **Do NOT** parallelize emitter fetches.
- **Labels:** monolith(file-only), hot-path-adjacent
- **Dedup note:** cataloged codex-171-16; status = already fn-split, file-carve pending.

#### [A9-go-api-cli] F10 — `cmd/cli/show.go` per-command split holds; `handleShow` is a 326-LOC nested dispatch

- **Severity:** Low · **Confidence:** High · **Refactor class:** (A) MECHANICAL/SAFE
- **Dedup tag:** STATUS-UPDATE(cataloged cmd/cli/show.go)
- **Evidence:** 2,100 LOC. The only genuine god-fn is `handleShow`(14→340 = **326 LOC**): a
  deeply-nested `switch args[0] { case "chassis": switch args[1] { … } }` mapping arg tuples to
  `showText("chassis-cluster-…")` topic strings. The remaining ~45 fns are thin (`showText`/
  `showTextFiltered` proxies to gRPC + small local formatters like `printSessionEntries`,
  `showNAT*Summary`). So the cataloged "per-command show files" split is valid but the file is
  mostly a **dispatch table masquerading as code** — most of `handleShow` could be a declarative
  `map[argpath]topic` instead of nested switches.
- **Proposed decomposition:** (a) carve per-domain files (`show_security.go`, `show_nat.go`,
  `show_flow.go`, `show_routing.go`, `show_system.go`) as cataloged; (b) additionally, replace the
  `handleShow` arg-tuple→topic nesting with a small dispatch table so adding a topic is one row.
- **Hot-path preservation:** N/A — remote CLI.
- **Tests + gate:** the cmd/cli `show_*_test.go` suite (many); `make test-go`.
- **Why it matters:** the dispatch nesting is where new `show` commands get wired; a table removes
  the depth and the copy-paste `if len(args) >= N` guards (several already have dead fall-through,
  e.g. `control-plane` returns the same topic in both branches).
- **Fix direction:** per-command carve + tableize `handleShow`.
- **Labels:** monolith, dispatch, remote-cli
- **Dedup note:** STATUS-UPDATE of the cataloged item; adds the god-fn identity (handleShow) and
  the table-dispatch angle.

#### [A10-go-services] F-9 — ddns/surface_a.go: split + field-grouping still NOT landed (status)

- **Title:** Surface-A manager remains a 1,957-LOC unsplit FSM; no #4407-style field-grouping applied.
- **Severity:** Medium (size), Low (urgency)
- **Confidence:** High
- **Refactor class:** B
- **Dedup tag:** STATUS-UPDATE(codex-171-28).
- **Evidence:** file is 1,957 LOC (catalog listed 1,841/1,957 — at the top of that range now). The `surfacea/{scope,state,reconcile,publish,withdraw,orphan,status,backend_resolve}.go` split has NOT landed. `SurfaceAManager` (:313) is still a flat struct — degraded/runtime/orphans/forceRefresh/newBackend/backend/httpClients/counters are all top-level fields (heavily documented, but NOT grouped into sub-structs the way daemon.go's #4407 grouped its 150+ fields). God-fns: `reconcileScopeLocked` (:942) 167 LOC, `publishLocked` (:1153) 196 LOC, `withdrawOwnedLocked` (:1349) 73.
- **Hot-path preservation analysis:** none. Invariants: degraded fail-CLOSED posture (:328), orphan re-derivation, per-RG writer gate — all documented in-struct; a split must keep the fail-closed degraded gate ahead of any publish.
- **Tests + gate:** `surface_a_test.go` (802), `surface_a_provider_change_3735_test.go`, `surface_a_http_test.go`, `surface_a_rfc2136_test.go`, `surface_a_lockio_test.go`, `scope_test.go`. Gate: `go test ./pkg/ddns/...`.
- **Why it matters:** confirms the catalog item is still fully open; `publishLocked` (196) is a genuine god-fn worth peeling first.
- **Fix direction:** land the surfacea/ file split; `publishLocked`/`reconcileScopeLocked` are the first extraction targets.
- **Labels:** refactor, class-B, status.
- **Dedup note:** cataloged codex-171-28; status = open, no increment landed here (contrast daemon.go which got field-grouping).

#### [A10-go-services] F-10 — Cataloged monoliths confirmed open (batch status)

- **Severity:** informational · **Confidence:** High · **Class:** per-catalog · **Dedup tag:** STATUS-UPDATE.
- **routing/rules.go (1,274):** three routing domains confirmed present and fused — `nextTableManager` (:76), `ribGroupManager` (:206), PBR (`PBRRule` :454 + `resolvePBRDirection` :1068, 111 LOC). Cataloged codex-156. Still unsplit. Each has its own `Apply`/`clear`; a per-domain file split (`rules_nexttable.go`/`rules_ribgroup.go`/`rules_pbr.go`) is Class A. Invariant: next-table/ribGroup RuleAdd-failure handling (codex-156 H04/H05) must stay with its domain.
- **dhcp/dhcp.go (1,800):** v4/v6 client FSMs confirmed parallel — `runDHCPv4` (:683) 179 LOC, `runDHCPv6` (:1096) 177 LOC, `leaseFromACKv4` (:936) 102, `parseV6Reply` (:1426) 98, `dhcpExchangeMode.String` (:91) large state enum. The cataloged shared `lease_fsm.go` seam is REAL: runDHCPv4/runDHCPv6 share the same select/renew/rebind skeleton and would collapse onto one generic FSM parameterized by AF. Split into `client_v4.go`/`client_v6.go`/`lease_fsm.go`/`parse.go`/`address.go`. Cataloged codex-173-11.
- **snmp/agent.go (1,519):** 57 functions, NONE >60 LOC — a broad dispatch grab-bag (BER encode + OID table + ifTable MIB + PDU dispatch + trap queue across `Agent`/`IfData`/`ifSnapshot`/`varbind`/`trapJob`). Pure Class-A mechanical file split (`agent_runtime/pdu_v2c/oid_table/if_table/ber/traps_queue.go`, cataloged codex-173-19). No god-fn — size is spread, so the split is low-risk.
- **policymatch/policymatch.go (1,679):** god-fns `SelectorArgs.Query` (:479) 192 LOC, `ValidateProtocol` (:176) 173, `Match` (:791) 162, `matchSingleApp` (:1499) 101. Cataloged codex-171-21. Invariant: `portMatches` fail-open-on-Atoi (compiled-88 HIGH) lives here — keep validation with match. Split by selector/query/match/app/render.
- **eventengine/engine.go (1,259):** cataloged codex-173-9. No single god-fn (largest `applyOnce` 91, `newPolicyRuntime` 86). Split is Class-A file partition (runtime_set/matcher/planner/action_queue/worker).
- **ipmon/ipmon.go (1,016):** cataloged codex-173-10. `run` (:822) 95 largest. Overlay/FSM/actuator/status all in one; the file header documents the single-decision-point ActiveOverlay contract — the split must keep the overlay-winner-resolution as one unit (both FRR-render and userspace-snapshot consumers read it).
- **configstore/store_commit.go (828) / store.go (603):** cataloged codex-173-2. Durability-ordering (promote-after-persist, SyncDir batching) is load-bearing per engineering-style persistence classes — STATUS only, do not disturb without the durability gate.


## 8. Suggested issue split (sequenced — small PRs, mechanical before behavioral, each behind existing gates)

Ordering principle: tooling first (so the SSOT stops lying), then pure test moves (zero production diff), then Go class-A mechanical splits, then Go guarded splits, then Rust hot-path class-B/C splits each with a disassembly diff + the cluster gates. Each numbered item is one issue; sub-bullets are single-PR increments.

**Wave 0 — tooling (1 small PR; makes every later PR measurable)**
1. `scripts/refactoring-audit.sh`: add `tests_*.rs` to the exclusion patterns AND emit a production-LOC column (strip from the first top-level `#[cfg(test)]`/`mod tests`); regenerate `docs/refactoring-audit-current.txt`; `make audit-check`. (A1-F6 + A3-F2/F4 heatmap drift; labels: `refactor`, `tooling`.)

**Wave 1 — pure test relocation (class A; no production bytes change)**
2. Inline-test moves to `#[path]` siblings (one PR each, `cargo test` count-identical): `cos/queue_service/mod.rs` cfg(test) legacy selectors (A3-F2); `cold_path_hist.rs` ~915-LOC block (A3-F4); `poll_stages.rs` ~2,555-LOC block (A1-F2); `reject_reply.rs` ~1,760-LOC block (A1-F5); `state_writer.rs` (A5-F5).
3. Giant test-file splits colocated with production seams (start with the two that gate Wave 4): `afxdp/tests.rs` 13,598 — move the `txn_*` differential cluster as an intact unit first (A1-F4); `manager_test.go` 6,782 per the cluster→file map (A7-F-A7-10); then `parser_security_test.go` (A6-F7), `frr_test.go` (A10-F-12), and the A4-F17 mapping for `policy_tests.rs`/`session/tests.rs`.

**Wave 2 — Go mechanical splits (class A; `make test-go` + package tests)**
4. `pkg/dataplane/userspace/protocol.go` → 6 domain files (A7-F-A7-6; wire-parity tests gate); `format/status.go` section split (A7-F-A7-9); peel `manager_counters.go` out of `manager_ha.go` (A7-F-A7-3).
5. `pkg/config`: `runUniformGates` table-drive (A6-F1; golden_4406 + strict-wiring canary gate the order); `ValidateConfig` head-carve into per-domain warn helpers (A6-F2); extract `defaultLenientOpts()` for the byte-identical 98-field literal (A6-F3); `compileProtocols` per-protocol split (A6-F4); `compiler_nat.go` 4-file split carrying the shared scope helpers in `_scope.go` (A6-F5); per-child dispatch extractions (A6-F6).
6. `pkg/api` + `pkg/grpcapi` + CLI: `newCollector` per-domain descriptor files (A9-F1); `metrics_userspace.go` file-only carve preserving single-`Status()` (A9-F2); `server_diag.go` 3-way carve (A9-F5); `handleShow` tableization (A9-F10).
7. Services: `Runner.Run` phase split with journal-ordering guard (A10-F-2); `EventReader` decomposition with swap-then-close ordering (A10-F-6); `renderRouteMapForPolicy` (A10-F-3, sanitize-belt tests travel); `runRelaySession` (A10-F-4); `ipsec renderConfig` (A10-F-5); `snmp/v3.go` USM/PDU split (A10-F-7); `ddns/manager.go` field-grouping à la #4407 (A10-F-8); `surface_a.go` `publishLocked` first (A10-F-9).
8. Daemon/HA mechanical slices: `daemon_system.go` grab-bag split (A8-F10); `cluster/status.go` formatting split (A8-F11); `nftRulesFromTerm` lowering split (A8-F7); `buildRA` option assembler (A8-F12).

**Wave 3 — Go guarded splits (class B/C; behavioral gates named per item)**
9. `pkg/sessionview` shared session view/filter/projection — RESOLVES the REST-vs-gRPC egress-iface drift; behavior decision required on which semantics is correct before merging (A9-F3; gate: REST+gRPC+CLI session tests + a new drift-pin test). Then `pkg/showtext` (A9-F4) and the show-interfaces reth helper (A9-F6, fable-168 §4.2).
10. `routing/tunnel.go` Build/Apply/Commit lock narrowing — class C; keepalive generation counters and #1919 EBUSY retention preserved; gate: routing tests + cluster smoke (A10-F-1).
11. `compileZones` five-domain decomposition — preserve #1922 protected-set + device-map leave-alone skip (fail-open surface); gate: iface reconcile tests + standalone deploy ping matrix (A7-F-A7-1). `applyHelperStatusLocked` phase split under the cataloged 6-file seam (A7-F-A7-2).
12. `daemon_run.go::Run` startup/shutdown phase extraction (A8-F1) and `applyConfigLocked` ApplyContext phases (#4407, A8-F2); gate: `make test-deploy` + restart-connectivity.
13. HA/VRRP: `vrrp/instance.go` 6-file split with the GARP epoch/dampener and preempt-gate preservation analysis (A8-F3); `startClusterComms` wiring split (A8-F5); `sync_conn.go` generation-guard seam (A8-F4); `conntrack gc.go sweep` v4/v6 dedup preserving HA-callback order (A8-F6). GATE for every item: `make test-failover` + `make test-ha-crash` on the loss userspace cluster.

**Wave 4 — Rust hot-path splits (class B/C; EVERY PR ships a `cargo asm` (or objdump) diff of the named hot fns + full `make test`; cluster CoS/fairness smoke where CoS is touched)**
14. #4404 increments, in order (A1-F1): (a) NAT64 pre-routing cold block (~487 LOC) → `stages/nat64_pre_routing.rs`; (b) forward-resolve block; (c) disposition-dispatch — each returning `StageOutcome` so the #2208 recycle-once contract stays single-exit; txn_* differential tests must be moved intact FIRST (Wave 1 item 3).
15. `worker_loop` cold-cadence extraction to `#[cold]` helpers (class C — icache win; A1-F3); asm diff must show the hot poll call unchanged.
16. #4408 increment 2: extract the Phase-8 size-changing build body (~545 LOC) from `enqueue_pending_forwards` returning the `retained_source_frame` decision (A3-F1); then waterfill epoch-refill block extraction + settle/scratch cold split (A3-F2).
17. Forwarding: fix `DEFAULT_V4_TABLE.to_string()` → `&'static str` (perf bug, one-liner — land before or with the facade split, A2-F1); `forwarding/mod.rs` facade split per validated fn→file map (A2-F3); `ForwardingState` 64-field hot/cold regroup WITH a new `const` size/offset pin (A2-F7); delete dead `IcmpTeRateLimiter` (A2-F2).
18. Session/policy/NAT: land a `const _: () = assert!(size_of::<SessionEntry>() == …)` pin FIRST (A4-F4 — no pin exists today), then the {ha,limit,timeout,delta} peels; fix hit-path `metadata.clone()` (A4-F5); policy.rs parse-phase split per the A4-F1 map (#4421); `match_source_nat_result_for_tuple` split (A4-F7); NAT allocator `#[cold]` GC extraction (A4-F8, #4409); `check_packet_with_zone_id_opts` decomposition (A4-F10); `session_glue` god-fns (A4-F14); `parse_term` (A4-F15).
19. CoS types: `types/cos.rs` cold-config peel to `cos_config.rs` (A3-F3); `lease.rs` status-getter peel to `lease_status.rs`, acquire-loop left intact (A3-F5); `cos_classify.rs` within-file decomposition before the next feature lands (A3-F6).
20. Control-infra (mostly A/B, lower urgency): `event_stream/codec.rs` named-offset SSOT (A5-F1); `coordinator/status.rs` projection split (A5-F2); wg_control / event_stream / server-helpers increments per validated catalog seams (A5 status blocks).

**Explicitly NOT filed (D-class, recorded in §6.3)**: poll_stages 6-way production split; reject_reply/state_writer/xsk_ffi/binding.rs/userspace-xdp-lib splits; cmdtree tree-literal split; retirement-canary split; all previously recorded D-class items re-confirmed this run.

---

*End of report. Full per-finding dedup notes are inside each block; the working set (dedup corpus summary, per-agent raw reports, merge script) lives in the session scratchpad.*
