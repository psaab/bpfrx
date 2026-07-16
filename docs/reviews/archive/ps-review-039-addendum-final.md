
---

## Coverage & verification summary

**Files reviewed / total:** Top ~60 largest files inspected from 250k LOC Go + 142k LOC Rust prod (excluding vendored/generated/target/tests).
Top-inventory files covered: all 10 batch areas, 60+ largest files, all top-Rust-non-test (>1000 LOC) and top-Go-non-test-non-gen (>1000 LOC).

**Findings per area:**
- A1a (poll_descriptor): 3 findings (1 B-component update to #4404 with new measurement + 2 D-negatives: poll_stages.rs + reject_reply/filter already extracted)
- A1b (TX dispatch): 5 findings (2 B-component: dispatch god-func remnant Phase 8 + tx/cos_classify 7-resp, 1 D tx/transmit already clean, 2 minor D/C: tx/rings mixed disciplines + tx/drain leftover)
- A1c (CoS): 3 findings (1 B: CoSInterfaceRuntime 28-field god-struct, 1 D waterfill already filed #4408, 1 D shared_cos_lease cluster well-split)
- A1d (Session table): 3 findings (1 D-file-split-as-code-motion not true decomposition, 1 C SessionEntry hot/cold Arc clone per packet, 1 D leaf modules clean) — overlaps #4421/#4422 but adds field-level hot/cold inventory
- A1e (Forwarding/neighbor): 4 findings (1 C ForwardingState 65-field god-struct perf-positive, 1 B neighbor.rs 4-resp monolith, 1 B forwarding/mod.rs 2822 LOC 5 god-fns, 1 D forwarding_build already clean 8 files)
- A1f (Screen/frame/filter): 4 findings (1 B screen/mod.rs 16-checks SYN-flood god-func, 1 B frame/inspect.rs EH walker dup, 1 A frame/mod.rs 6-resp kitchen sink, 1 D scan+wg+runtime already clean)
- A1g (Remaining Rust infra): 5 findings (2 A: wg_control 2280 monolith + server/helpers dumping ground, 1 optional event_stream, 3 D negatives: wg/engine, types/cos, etc.)
- A2 (NAT): 5 findings (1 C nat/allocator PortAllocatorShared perf-positive, 1 B nat/source god-function, 1 A compiler_nat.go 6-file motion, 2 D negatives: nat/dest + nat/tests already split)
- A3 (Go config compilers): 5 findings (4 A: compiler_validate_warn, compiler_system, compiler_services, compiler_nat helpers/validators; 1 D: compiler_uniformgates + types already well-split)
- A4 (Go dataplane+daemon+cluster+routing): 5 findings (5 A: protocol.go wire-format 12 domains, sync_conn.go HA gen-guard ordering, tunnel.go 5-resp, compiler_validate_warn.go 35 funcs, metrics_descriptors.go 279 NewDesc; plus 3 D-negatives: maps_sync, vrrp/instance single SM, daemon god-struct already #4407)

**Classification totals (actual new findings only, excluding already-filed #4404-#4421):**
- (A) MECHANICAL / SAFE (cold path, pure code-motion, no hot-path risk): ~14
- (B) REQUIRES GUARDRAILS (hot/warm path, safe only if guardrails met): ~8
- (C) PERFORMANCE-POSITIVE (hot/cold cache win / lock narrowing / single-writer): ~4
- (D) DO-NOT-SPLIT (genuinely cohesive / already well-decomposed / threshold not exceeded): ~11
- Total findings across batches: 41 (mix of new + enriched + D-negatives)

**Verification approach per class:**
- (A) Mechanical: `go build ./...` + `cargo build -p userspace-dp` + `go test ./...` + `cargo test -p userspace-dp` byte-identical (sorted decl-NAME set unchanged per #4144 discipline), incremental-build timing improvement
- (B) Hot-path guardrails: `cargo asm` / `objdump -d` disassembly diff (no new alloc/call on hot path), `perf stat` cache-miss/branch-miss counters, criterion bench delta, `size` on object, + existing behavioral gates (`make test`, `test-failover`, CoS smoke/fairness)
- (C) Performance-positive: same as (B) + explicit measurement showing improvement (cache-miss reduction, build-time improvement, branch-predictor win)
- (D) Negative: no change needed, documenting why

---

## Suggested issue split — sequenced so each PR is small, independently reviewable, behind existing gates

### Phase 1: Go mechanical splits (safe, driveable-now, largest ROI for build-time + reviewability)

1. **compiler_validate_warn.go 3330 → 5 per-domain files** — (A) mechanical. Largest Go file.
   - `compiler_validate_warn_nat.go`: validateNAT warnings
   - `compiler_validate_warn_security.go`: policy/zone/screen
   - `compiler_validate_warn_forwarding.go`: routing/tunnel/VRF/interface
   - `compiler_validate_warn_ddns.go`: DDNS/dhcp-server
   - `compiler_validate_warn_routing.go`: BGP/CoS/multicast/misc
   - Gate: `go build ./...` + `go test ./pkg/config/...` green, decl-NAME set identical.
   - Labels: `refactor`, `go`, `config`

2. **protocol.go 2979 → 12 domain files** — (A) mechanical, 72 types across 12 wire domains.
   - `protocol/control.go` (ControlRequest/Response), `protocol/snapshot.go` (ConfigSnapshot+~20 subtypes),
     `protocol/status.go` (ProcessStatus+~40 subtypes), `protocol/binding.go` (already exists Rust side),
     `protocol/cos.go`, `protocol/nat.go`, `protocol/policy.go`, `protocol/filter.go`, `protocol/ha.go`,
     `protocol/session_sync.go`, `protocol/eventstream.go`, `protocol/docs.go` (constants)
   - Gate: `go build ./...` + `cargo test -p userspace-dp` (Rust protocol/tests.rs decodes Go JSON).
   - Labels: `refactor`, `go`, `dataplane`, `protocol`

3. **compiler_system.go 1881 + compiler_services.go 1821 → per-domain files** — (A) mechanical.
   - `compiler_system_login.go` + `_snmp.go` + `_chassis.go` + `_ddns.go` + `_userspace.go`
   - `compiler_services_rpm.go` + `_dhcp.go` + `_flow.go` + `_ip_monitoring.go` + `_event.go`
   - Labels: `refactor`, `go`, `config`

4. **compiler_nat.go 2529 → 3-4 files + move strict gates** — (A) mechanical with subtlety.
   - `compiler_nat_helpers.go` (natAddrFamily etc. shared helpers — note: used in 3 files),
     move `validateNATHostMaskStrict` + `validateNPTv6Strict` to `compiler_validate_strict_nat.go`
   - Gate: `go build ./...` + `go test ./pkg/config/...`.
   - Labels: `refactor`, `go`, `nat`, `config`

5. **metrics_descriptors.go 1896 → helper methods** — (A) mechanical.
   - `initGlobalDescriptors`, `initUserspaceDescriptors`, `initCoSDescriptors`, `initBindingDescriptors`,
     `initWorkerDescriptors`, `initFairnessDescriptors`, `initSystemDescriptors` — `newCollector` becomes 20-line orchestrator.
   - Gate: `go test ./pkg/api/...`.
   - Labels: `refactor`, `go`, `metrics`

### Phase 2: Rust mechanical splits (safe, cold path or same-crate boundary)

6. **wg_control.rs 2280 → wg_control/{socket,loop,dispatch,handshake,poll}.rs** — (A) mechanical, cold (100ms poll).
   - Labels: `refactor`, `rust`, `wg`

7. **server/helpers.rs 1292 → helpers/{status,session_sync,binding_plan,hash,lifecycle}.rs** — (A) mechanical.
   - File header says "Pure relocation pending further split."

8. **frame/mod.rs 1710 → frame/{nat,prep/inject,verify,nat64_fwd}.rs** — (A) mechanical.
   - 9 prior extractions already done (#988/#989/#1046/#1352/#1440), this is the final 6-resp kitchen sink cleanup.

9. **event_stream/mod.rs 1693 → transport+sequencing+clock split** — (A) mechanical, optional.
   - Defer if count is low; easy win when next feature touches event_stream.

### Phase 3: Go ordering-sensitive / Rust hot-path-adjacent (requires /triple-review)

10. **sync_conn.go 1858 → sync_conn/{gen_guard,fabric,state_machine,batch}.go** — (B) ordering-sensitive.
    - Gen-guard stamp→queue→take, bulk reset, fabric preference (#2198/#2221/#2995, #4090/#4360).
    - Requires preserving generation-guard state machine comments + single-active-fabric invariant.
    - Gate: `go test ./pkg/cluster/...` + `test-failover` smoke.
    - Labels: `refactor`, `go`, `ha`, `hot-path-adjacent`

11. **tunnel.go 1877 → tunnel/{lifecycle,keepalive,wg_mtu,vrf,address}.rs equivalents** — (A/B) mixed.
    - Keepalive Axis D commit-after-success lock-free is the sensitive part.

### Phase 4: Rust hot-path (requires /triple-review, disassembly + bench gates)

12. **PortAllocatorShared hot/cold split** — (C) performance-positive. Cache-line win: hot bitmap+CAS vs cold stats/GC/persistent-leases.
    - Guard: `benches/snat_allocator.rs` must not regress, `#[repr(align(64))]` cache-line pad, no new pointer chase.
    - Verification: criterion bench delta, `perf stat` LLC-load-miss before/after, `cargo test -p userspace-dp`.
    - Labels: `refactor`, `rust`, `nat`, `hot-path`, `x-hpc`

13. **nat/source.rs match_source_nat_result_for_tuple 336 LOC → classify_l4_mode() enum + allocate_pool_v4/v6** — (B) hot-path.
    - Gate: `cargo test -p userspace-dp -- nat`, session sync during failover.

14. **ForwardingState 65-field god-struct → hot FIB vs cold config** — (C) performance-positive.
    - Immediate: `#[repr(C)]` + hot-field-first reorder (zero-risk).
    - Then: `ForwardingFib(Arc)` SoA split — workers hold hot FIB separately from cold config.
    - Gate: `cargo test -p userspace-dp` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200 ≥23Gb/s, no regression`.

15. **SessionTable + SessionEntry hot/cold field separation** — (C) performance-positive + (D) field map for true 7-group decomposition.
    - SessionEntry Arc clone per packet — 10ns+ win expected at ~7.5M pps/worker via SessionHot/SessionCold inline split.
    - Gate: `lookup_with_origin` micro-bench, `cargo test`, `test-failover`.
    - Labels: `refactor`, `rust`, `session`, `hot-path`, `x-hpc`

16. **neighbor.rs 2036 → neighbor/{probe,kernel,monitor,warmer}.rs + gc.rs** — (B).
    - GC path cold, probe craft must preserve `trigger_kernel_arp_probe` allocation-freedom.

17. **screen/mod.rs SYN-flood god-function → screen/{syn_flood,flood,missing_profile}.rs** — (B).
    - Keep `#[inline(always)]` for hot-path preservation.

18. **frame/inspect.rs EH walker dedup → inspect/{ext,frag,flow,filter}.rs** — (B).
    - Single `walk_ipv6_ext_headers` shared impl, 5× call sites.

### Phase 5: Hardest hot-path god-functions (requires deep /triple-review, NOT driveable-now)

19. **poll_descriptor/mod.rs poll_binding_process_descriptor 4724 LOC + poll_stages.rs + reject_reply + filter** — (B) requires guardrails.
    - Already filed #4404 (reported 1368 LOC, now 4724 — growth). This audit provides new measurement + decomposition angles.
    - 6 incremental PRs ordered by risk: flowless A → telemetry cold outline C → NAT pre-routing B → host-local dedup B → session install B → hit/miss split B with PacketCtx.
    - Guardrails: single-recycle invariant (39 push sites), Junos order 3× duplication, no alloc, inlining, `FORCE_OVERSIZED`/`FORCE_TUPLE_MISMATCH` gates.
    - Do NOT attempt without disassembly baseline + `flowless_local_delivery_tests` + `inplace_randomized_sequence`.
    - Labels: `refactor`, `rust`, `hot-path`, `x-hpc`

20. **tx/dispatch/mod.rs enqueue_pending_forwards 1048 + tx/cos_classify.rs 7-resp + CoS waterfill** — (B)/(C).
    - tx/dispatch: `dispatch/forward_build.rs` (Phase 8 cascade), `tcp_seg.rs`, `fabric.rs` + single-recycle + direct-TX + fabric triple repetition.
    - Already filed #4408. New detail: Phase 8 + direct-TX + fabric breakdown + exact coupling count.
    - Labels: `refactor`, `rust`, `tx`, `hot-path`, `x-hpc`

---

## Negative results (D — do-not-split, genuinely cohesive)

### D-01: poll_stages.rs — well-decomposed (9 stage fns, all #[inline], 304 LOC largest)
Already extracted stages; splitting would duplicate VLAN logical-ifindex logic that caused #2145/#3022 bugs.

### D-02: reject_reply.rs + filter.rs — correctly extracted cold-path modules
Both #[cold] #[inline(never)], exemplary inline policy (cheap guards #[inline], heavy bodies cold). 5-stage pipeline must stay linear for #3656 H11/H12 ordering; Junos order must stay atomic (#3485).

### D-03: tx/transmit/*.rs — CLEAN SEPARATION, textbook (#1354)
6-phase split (rewrite/verify/finalise/write/stage) is exemplary. No further action.

### D-04: tx/rings.rs — mixed ring disciplines — minor, defer

### D-05: tx/drain/mod.rs — orchestrator clean at 35 LOC, leftover CoS ingest 235 LOC → `cos_leftover.rs`/`cos_ingest.rs` only if team anticipates churn.

### D-06: CoS waterfill — already #4408, new angle (f64 fraction calc 37 LOC extraction)

### D-07: shared_cos_lease cluster (backlog+vtime well-split), CoSInterfaceRuntime well-decomposed post-#1035

### D-08: session leaf modules — key.rs (pure NAT key transforms), wheel.rs (power-of-two), ctx.rs (#1357), entry.rs type extraction — all exemplary.

### D-09: forwarding_build/ — well-decomposed (#1342, 8 files, linear chain, documented ordering invariant), cos.rs 850 LOC has 3-way split

### D-10: forwarding/mod.rs well-decomposed scaffolding — no action (from a1e), but D-01 65-field god-struct still applies to types/forwarding.rs

### D-11: nat/destination.rs — cohesive single-resp DNAT table, under threshold

### D-12: nat/tests — already split per #4409 (was 8685 single file), largest 3828

### D-13: wg/engine.rs + wg/cookie.rs — single-responsibility WG protocol

### D-14: types/cos.rs, types/forwarding.rs, protocol/binding.rs — cohesive single-responsibility

### D-15: event_stream/mod.rs — defer, borderline but cohesive transport+sequencing+clock

### D-16: compiler_uniformgates.go — single-func orchestrator, already #4406 step 4 split result

### D-17: compiler_validate_strict_filter.go — single-domain, already #4405 per-domain split result

### D-18: compiler_interfaces.go, types_system.go — genuinely cohesive or touches 20+ consumers

### D-19: maps_sync.go, vrrp/instance.go — cohesive single-responsibility (vrrp is one RFC 5798 SM)

### D-20: daemon_run.go/daemon_apply.go — already #4407

---

## Labels for all findings

Common: `refactor`, `hot-path` (for B/C on per-packet), `x-hpc` (cache-line/layout/atomics), `cold-path` (A mechanical), `monolith`, `god-struct`, `god-function`

Per-finding: `go-config`, `rust-dataplane`, `nat`, `session`, `forwarding`, `neighbor`, `screen`, `frame`, `wg`, `event-stream`, `protocol`, `sync`, `tunnel`, `metrics`, `cos`, `tx`, `coS-queue`

---

## Verification matrix

| Finding class | Inlining | Alloc | Dispatch | Layout | Locality | Lock scope | Verification |
|--------------|----------|-------|----------|--------|----------|------------|-------------|
| (A) Mechanical | Free (same crate TU, or Go same package) | N/A (cold path, config time) | N/A | N/A | N/A | N/A — must not widen | go build/test, cargo build/test, decl-NAME set identical, incremental-build timing |
| (B) Hot-path guardrails | Require #[inline] after move, same crate free OR explicit #[inline] on new module boundary, confirm via cargo asm / objdump -d diff | No Box/Vec/String/clone on per-packet path | No trait objects on hot, prefer enum+match devirtualized | Carry const _: () = assert!(size_of/align_of...) | Keep hot fields in one cache line, cold fields separated | Narrow critical section, preserve concurrency invariants (single-writer-per-worker, per-CPU, lock-free/seqlock, atomic ordering) | cargo asm / objdump -d disassembly diff + perf stat cache-miss/branch-miss + criterion bench + size on .o + make test + test-failover + CoS smoke |
| (C) Perf-positive | Same as (B) | Same as (B) + must measure improvement | Same as (B) | Same as (B) + explicit SoA / AoS→SoA proof | Must measure: perf stat LLC-load-miss reduction, or build-time improvement, or branch-miss reduction | Lock-scope narrowing that reduces contention | Same as (B) + explicit perf measurement showing win (cache-miss reduction, build-time, bench delta) |
| (D) Do-not-split | N/A — no change | N/A | N/A | N/A — layout already correct | N/A — already tight | N/A — already correct scope | No change, documenting why |

---

*Base commit: f70146951583823a5ace87b0b11a2e58f46e8db9*
*Generated: 2026-07-08T15:54:39.945501+00:00*
*Output: /tmp/ps-review-039.md (this file)*

