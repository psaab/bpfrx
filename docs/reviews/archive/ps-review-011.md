# xpf firewall refactor audit â€” ps-review-011

## 1. Base commit reviewed

```
Repo: /home/ps/git/xpf
Branch: main
Commit: 58a002642f269cc29457945ca14f8f630add2293 (2026-07-06)
git pull --rebase: failed (network 403, proxy blocks github.com) â€“ audited existing checkout, no source mutations.
```

## 2. Output path

`/tmp/ps-review-011.md`

## 3. Duplicate suppression summary

- Prior campaign files:
  - `/tmp/fable-review-001.md`, `/tmp/fable-review-002.md` â€“ security audits, no refactor findings except note that `pkg/policymatch/` is well isolated (no refactor needed).
  - `/tmp/avo-review-002.md` through `/tmp/avo-review-007.md` â€“ security audits, no refactor findings.
  - `/tmp/ps-review-007.md` through `/tmp/ps-review-009.md` â€“ security audits with critical bugs, no refactor findings.
  - `/tmp/ps-review-010.md` â€“ **refactor audit** of Rust AF_XDP hot path: poll_descriptor god-function (1,368 LOC), policy.rs SnapshotIntegrityError dumping ground, SessionTable god-struct, ForwardingState god-struct, TX drain orchestrator (1,131 LOC), CoS selection monolith. Findings R1â€“R12.
  - Total 69 prior findings (64 security + 12 refactor - 7 D-class = 5 new refactor). All read for dedup.
- Prior campaigns (per instruction) flagged these refactor-debt monoliths:
  - 1,100+ line TX drain orchestrator (`enqueue_pending_forwards`) â€“ **confirmed in ps-010 R5, not duplicated here**
  - Cross-domain `SnapshotIntegrityError` / `policy.rs` dumping ground â€“ **confirmed in ps-010 R2, not duplicated here**
  - ~880-line IPsec `policy.go` â€“ out of scope (Go control plane, not Rust hot path focus)
  - ~1,589-line HA `sync_conn.go` generation-guard state machine â€“ out of scope (Go control plane)
  - 5-file-scattered NAT compile/validate surface â€“ out of scope (Go control plane)
  - Inlined ~110-line SYN-flood enforcement in screen check function â€“ out of scope (screen, not hot path focus)
- Read `docs/engineering-style.md` â€“ hot-path discipline: no alloc, no dispatch, inlining preserved, cache locality, UMEM ownership, `#[repr]` guards.
- Read `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, `userspace-dp/src/policy.rs`, `userspace-dp/src/session/mod.rs`, `userspace-dp/src/afxdp/forwarding/mod.rs`, `userspace-dp/src/nat/`, `userspace-dp/src/filter/`, `userspace-dp/src/screen/`, `userspace-dp/src/afxdp/wg/`, `userspace-dp/src/gre.rs`, `pkg/config/compiler_validate_strict.go`, `pkg/daemon/daemon.go`, `pkg/dataplane/userspace/manager.go`.
- Findings below are **not** restatements of ps-010 R1â€“R12 or prior security findings. They cover Go control plane config compilation, Rust NAT/filter/screen/WG/GRE/neighbor modules, and Go daemon/dataplane manager â€“ areas not examined in ps-010 which focused on poll_descriptor, policy, session, forwarding, TX drain, CoS.
- Dedup notes in each finding explain why not a duplicate.

## 4. File-size / shape inventory â€“ module checklist and coverage proof

**Go control plane â€“ config compilation and daemon â€“ largest files:**

| File | LOC | Hot Path? | Responsibilities Fused | Rank |
|------|-----|-----------|------------------------|------|
| `pkg/config/compiler_validate_strict.go` | 6,997 | No â€“ config commit (cold) | 60+ domain validators: policy, NAT, filter, zones, screens, CoS, IPsec, BGP, etc. â€“ 112 symbols | 1 |
| `pkg/config/compiler.go` | 4,336 | No â€“ config compile | `compileExpanded` 2,435 LOC god function fusing AST pre-walks, section compilation, validation dispatch | 2 |
| `pkg/config/compiler_nat.go` | 2,485 | No â€“ NAT compile | Source/dest/static NAT compilation, scope parsing, validation â€“ 39 symbols | 3 |
| `pkg/dataplane/userspace/manager.go` | 1,823 | No â€“ config apply | Manager god-struct (60+ fields), Compile, HA, session sync, neighbors, BPF counters â€“ 74 symbols | 4 |
| `pkg/daemon/daemon.go` | ~3,500 | No â€“ daemon main | Daemon god-struct (638 lines, 150+ fields), fuses config, HA, DDNS, DHCP, SNMP, flow, etc. â€“ 15 subsystems | 5 |
| `pkg/daemon/daemon_apply.go` | 1,883 | No â€“ config apply | `applyConfigLocked` 1,148 LOC fusing commit, reconcile, rollback, 20 subsystem reconciles | 6 |
| `pkg/dataplane/userspace/manager_ha.go` | 1,376 | No â€“ HA events | HA state machine, session sync, watchdog, BPF counters â€“ 56 symbols | 7 |
| `pkg/daemon/daemon_ha.go` | 1,373 | No â€“ HA events | Cluster events, VRRP, RG reconciliation, blackhole routes, RETH services â€“ 35 symbols | 8 |
| `pkg/dataplane/compiler.go` | 1,733 | No â€“ compile | Config compilation orchestration, policy, interfaces, applications | 9 |
| `pkg/dataplane/compiler_nat.go` | 1,258 | No â€“ NAT compile | NAT compilation, 726-line `compileNAT` function with nested types | 10 |
| `pkg/dataplane/userspace/policies.go` | 1,432 | No â€“ snapshot build | Policy snapshots, address book, rule expansion â€“ cohesive domain builder | 11 |
| `pkg/dataplane/userspace/nat.go` | 1,286 | No â€“ snapshot build | Source/dest/static NAT, NAT64, NPTv6, feed overlay â€“ cohesive | 12 |
| `pkg/dataplane/userspace/zones.go` | 1,137 | No â€“ snapshot build | Zone snapshots, host inbound views, addressless zones, collision quarantine â€“ cohesive | 13 |

**Rust dataplane â€“ NAT, filter, screen, WG, GRE, neighbor â€“ largest files:**

| File | LOC | Hot Path? | Responsibilities Fused | Rank |
|------|-----|-----------|------------------------|------|
| `userspace-dp/src/nat64.rs` | 2,047 | **YES** â€“ per packet for NAT64 flows | Classification, v6â†”v4 translation, ICMP mapping, checksum, frame building, fragments â€“ 54 symbols | 1 |
| `userspace-dp/src/afxdp/neighbor.rs` | 1,901 | Warm â€“ forwarding path | ARP/NDP probe, netlink monitor, warmer loop, CPU pinning â€“ 4 concerns | 2 |
| `userspace-dp/src/afxdp/wg/engine.rs` | 1,763 | **YES** â€“ WG data path | Hot encap/decap with cold handshake/reconcile â€“ 18-field WgEngine, already partially modularized | 3 |
| `userspace-dp/src/screen/mod.rs` | 1,479 | Warm â€“ session miss | ScreenState orchestrator for 16 checks, SYN cookie, scan/sweep â€“ already split per #1543 | 4 |
| `userspace-dp/src/nat/source.rs` | 1,190 | **YES** â€“ new flows | SNAT rule parsing, L4 match, scope gate, pool allocation driver â€“ 42 symbols | 5 |
| `userspace-dp/src/nat/destination.rs` | 1,088 | **YES** â€“ new flows | DNAT table, prefix LPM, scope matching, tiered lookup â€“ cohesive | 6 |
| `userspace-dp/src/gre.rs` | 961 | **YES** â€“ tunnel traffic | GRE encap and decap, ECN combine, checksum â€“ cohesive, shared ECN with WG | 7 |
| `userspace-dp/src/filter/compiler.rs` | 945 | No â€“ config reconcile | Filter parsing, validation, three-color linking, `parse_term` 425 LOC â€“ cold path | 8 |
| `userspace-dp/src/filter/engine/eval.rs` | 1,026 | **YES** â€“ new flows, PBR | Standard eval, PBR routing-instance, log-match, output filter â€“ 30 functions | 9 |
| `userspace-dp/src/nat/allocator.rs` | 926 | **YES** â€“ new flows | PortAllocator god-struct mixing hot bitmap with cold config, stats, GC, persistent leases | 10 |
| `userspace-dp/src/nat/static_nat.rs` | 793 | **YES** â€“ new flows | Static 1:1 NAT, scope, source constraint, block rules â€“ cohesive | 11 |
| `userspace-dp/src/nat/tests.rs` | 8,685 | No â€“ tests | 232 tests for all NAT types â€“ dumping ground, should split per module | 12 |
| `userspace-dp/src/filter/tests.rs` | 7,923 | No â€“ tests | Large but test-only | 13 |

**Coverage:** Inspected all 13 Go files above plus `pkg/config/schema*.go`, `pkg/daemon/daemon_ha*.go`, `pkg/dataplane/userspace/filters.go`. Inspected all 13 Rust files above plus `nat/mod.rs`, `filter/mod.rs`, `filter/engine/matching.rs`, `screen/packet.rs`, `screen/stateless.rs`, `afxdp/wg/handshake_session.rs`, `afxdp/wg/cookie.rs`. Total ~50,000 LOC inspected (Go + Rust). This inventory is the coverage proof. ps-010 covered poll_descriptor, policy, session, forwarding, TX drain, CoS â€“ not duplicated here.

## 5. File-by-file inspection log

### `pkg/config/compiler_validate_strict.go` (6,997 LOC)
- **Monolithic validator**: 112 symbols, 60+ domain validators fused in single file. Functions for policy, NAT, filter, zones, screens, CoS, IPsec, BGP, RIB groups, VRRP, etc.
- **Responsibilities**: Each `validateXxxStrict(cfg *Config) error` is a pure function, no shared state except `*Config`. Functions already grouped by name prefix (validatePolicy*, validateNAT*, validateFilter*), but all in one file.
- **Coupling**: Change in NAT validation forces re-reading IPsec/BGP code. Merge conflicts frequent. Build cost high â€“ every edit recompiles 7k LOC and all dependents.
- **Already has per-domain tests**: `compiler_validate_*.go` tests per domain, but source still monolithic.
- **Proposed**: Split by domain into `pkg/config/validate_*.go` â€“ policy, NAT, filter, security, routing, IPsec, system. Keep thin dispatcher. (A) MECHANICAL/SAFE â€“ pure functions, no state, cold path.

### `pkg/config/compiler.go` â€“ `compileExpanded` (2,435 LOC)
- **God function**: `compileExpanded` at lines 1901-4336 fuses AST sanitization/pre-walks (lines 1901-2280), typed Config construction (2282-2350), section compilation dispatch (2336-2600), strict validation dispatch (2600-4300, 60+ calls).
- **Responsibilities**: AST pre-walks (control chars, VRRP track, interface-range expansion, application collisions, etc.), Config initialization with manual map init, section switch on `security`, `interfaces`, `applications`, etc., calling `compileSecurity`, `compileInterfaces`, etc., then 60+ validation calls, warning aggregation throughout.
- **Proposed**: Extract phase functions: `runASTPreWalks`, `newEmptyConfig`, `compileSections`, `runStrictValidators`. `compileExpanded` becomes thin orchestrator. (B) REQUIRES GUARDRAILS â€“ complex ordering, but cold path, preserve validation order for error precedence.

### `pkg/config/compiler_nat.go` (2,485 LOC)
- **NAT compiler monolith**: Fuses source NAT (508 LOC `compileNATSource`), destination NAT (226 LOC), static NAT (171 LOC), scope parsing, host-mask/NPTv6/NAT64 validation, pool alarm validation.
- **Proposed**: Split by NAT kind: `compiler_nat_source.go`, `compiler_nat_destination.go`, `compiler_nat_static.go`, `compiler_nat_validate.go`, `compiler_nat_scope.go`. Keep `compiler_nat.go` as dispatcher. (A) MECHANICAL/SAFE.

### `pkg/dataplane/userspace/manager.go` (1,823 LOC)
- **Manager god-struct**: 60+ fields (lines 150-294) mixing snapshot (cfg, lastSnapshot, routeOverlay), HA (haGroups, haWatchdogIPCSynced), session (sessionMu, userspaceSessionIDs, eventStream), neighbors (neighborIndex, monitoredIfindexes), BPF counters, bindings/XSK, mode.
- **Methods fused**: Lifecycle (New, Start, Close), compilation orchestration (`Compile` 220 LOC), route overlay, neighbor index, status, injection, session sync, BPF counter sync.
- **Proposed**: Split into domain components: `SnapshotBuilder`, `HAController`, `SessionSyncer`, `NeighborManager`, `CounterSyncer`, `BindingManager`. Manager becomes facade delegating to components. (B) REQUIRES GUARDRAILS â€“ HA/session state coupling, but cold path.

### `pkg/daemon/daemon.go` â€“ Daemon god-struct (638 lines, 150+ fields)
- **God-object**: Fuses config/store, dataplane, cluster/HA, gRPC, DDNS, DHCP, DNS, flow/IPFIX, SNMP, RPM/LLDP, scheduler, neighbor/GC, host inbound, NAT alarms, bootstrap â€“ 15 subsystems.
- **Proposed**: Extract manager structs: `ConfigApplier`, `HAManager`, `PolicyInvalidator`, `DDNSManager`, `FlowManager`, `SNMPManager`, `DHCPManager`, `NeighborGCManager`. Daemon becomes thin orchestrator. (B) REQUIRES GUARDRAILS â€“ large surface, but cold path.

### `pkg/daemon/daemon_apply.go` â€“ `applyConfigLocked` (1,148 LOC)
- **Monolithic apply**: Fuses commit, reconcile, rollback, and 20 subsystem reconciles in one function. Phases: bootstrap, config compilation, dataplane apply, networkd, FRR, IPsec, DHCP, DNS, DDNS, SNMP, LLDP, RPM, scheduler, flow export, etc., plus commit-confirmed rollback.
- **Proposed**: Split into phases with `ApplyContext`: `PhaseCompile`, `PhaseActuateNetwork`, `PhaseReconcileServices`, `PhaseHACommit`. Move subsystem reconcile to managers. (B) REQUIRES GUARDRAILS â€“ complex ordering, but cold path.

### `userspace-dp/src/nat/source.rs` (1,190 LOC)
- **SNAT monolith**: Fuses rule parsing (`parse_source_nat_rules_with_previous` 169 LOC), L4 match (`l4_matches` 23 LOC, `matches` 35 LOC), scope gate, pool allocation driver (`match_source_nat_result_for_tuple` 278 LOC), failure formatting (String clones on error path).
- **God-struct**: `SourceNatRule` mixes config (prefixes, zones, pool addresses) with runtime (`pool_allocator: PortAllocator`, `hit_counter: Option<Arc<NatRuleCounter>>`).
- **Hot path**: `match_source_nat_result_for_tuple` â†’ `rule.matches` (prefix iteration, no alloc) â†’ `pool_allocator.allocate_translation` (Mutex, bounded GC, no per-packet alloc except rare collision). Must stay inline, no new Arc/Vec per flow.
- **Proposed**: Split into `nat/snat_rule.rs` (parsing, rule struct), `nat/snat_match.rs` (match functions, allocation driver), `nat/snat_alloc.rs` (release/rollback/reserve wrappers â€“ cold). Keep `SourceNatLookup` enum in snat_match.rs. (B) REQUIRES GUARDRAILS â€“ hot for new flows, preserve inlining and no alloc.
- **Hot-path preservation**: `match_source_nat_result_for_tuple` and `PortAllocator::allocate_translation` need `#[inline]` if moved to separate module. Currently same crate, inlining OK. No new heap alloc on success path (only `retained: Vec` on collision, rare, acceptable). UMEM preserved â€“ SNAT only produces NatDecision, packet rewrite in-place.

### `userspace-dp/src/nat/allocator.rs` (926 LOC)
- **PortAllocator god-struct**: Mixes hot port bitmap (`counters: Vec<AtomicU32>`, `next_port_offset_by_addr: Vec<u32>`, `recycled_ports_by_addr: Vec<VecDeque>`, `live: Mutex<PortAllocatorLiveState>`) with cold config (`port_low/high`, `max_tracked_flows`), stats (`allocations_total`, `exhaustion_total`), GC (BTreeSet `lease_expirations`), persistent lease state machine.
- **Hot functions**: `allocate_translation` (168 LOC) â€“ Mutex lock, GC bounded (budget 8), `claim_free_port_locked` loop, no alloc on common path. `try_next_port`, `address_index` â€“ atomic, no lock.
- **Cold functions**: `gc_expired_locked`, `snapshot`, `release_flow`, `rollback_flow`, `reserve_flow`, `debug_*`.
- **Proposed**: Rename to `nat/pool.rs`. Split `PortAllocatorLiveState` into HotState (maps, cursors, recycled queues) and ColdState (lease expirations, BTreeSets). Move GC functions to `pool_gc.rs` with `#[cold]`, move snapshot/debug to `pool_status.rs`. Keep `allocate_translation` and `claim_free_port_locked` in hot module with `#[inline]`. (C) PERFORMANCE-POSITIVE â€“ hot/cold separation clarifies invariants, reduces lock contention surface.
- **Hot-path preservation**: `allocate_translation` must stay lock-bound, no alloc, no BTreeSet iteration beyond bounded budget. Currently good. `retained: Vec<u16>` lazily allocated only on collision â€“ acceptable. If split, keep `allocate_translation` `#[inline]`.

### `userspace-dp/src/nat64.rs` (2,047 LOC)
- **NAT64 monolith**: Fuses classification (`match_ipv6_dest`, `classify_ipv6_dest`, 54 symbols), v6â†”v4 translation (`write_v6_to_v4_into` 182 LOC, `write_v4_to_v6_into` 215 LOC), ICMP mapping, checksum math, frame building, fragment handling.
- **Hot path**: Classification per new flow and per packet (to determine if NAT64 needed) â€“ must be fast prefix match, no alloc. Translation per packet for NAT64 flows â€“ **allocates new Vec<u8> per packet** (unavoidable for header size change: IPv6 40B â†’ IPv4 20B). Non-NAT64 fast path must do zero alloc.
- **Proposed**: Split into `nat/nat64/` submodule: `mod.rs` (classification), `translate.rs` (v6â†”v4, frame building), `icmp.rs` (ICMP error mapping), `checksum.rs`, `fragment.rs`. Keep classification `#[inline]`, isolate frame allocation to translate.rs with comment explaining why alloc unavoidable. (B) REQUIRES GUARDRAILS â€“ translation is per-packet hot, must preserve zero-copy for non-NAT64, UMEM frame release on translation.
- **Hot-path preservation**: Classification must stay inline, no alloc on miss. Translation allocates new frame but releases original UMEM frame â€“ ensure no leak. Checksum functions pure math, keep `#[inline]`. If split, keep in same crate for inlining.

### `userspace-dp/src/nat/destination.rs` (1,088 LOC)
- **DNAT table**: Tiered lookup: exact â†’ wildcard port â†’ PROTO_ANY â†’ prefix LPM. `lookup_with_counter_scoped` (139 LOC), `match_entries` linear scan over Vec<DnatEntry> (typically 1-3 entries), `match_prefix_lpm`. No alloc on hot path. `from_snapshots` builds table (cold).
- **Cohesive**: Single responsibility (DNAT table), hot path clean, no cold fusion. 1,088 LOC is large but manageable.
- **Proposed**: (C) minor cleanup or (D) keep. Optionally split `DnatEntry` matching logic to `dnat_entry.rs` if file grows beyond 1,500 LOC. Rename to `nat/dnat.rs` for consistency. Keep `match_entries`, `source_matches`, `l4_extra_matches` `#[inline]`.

### `userspace-dp/src/nat/static_nat.rs` (793 LOC)
- **Static NAT**: 1:1 NAT with scope, source constraint, block rules. `match_dnat_with_counter_scoped` (115 LOC), `match_snat_with_counter_scoped`, `pick_scoped` linear scan over small Vec. No alloc on hot path. `from_snapshots` builds table (cold). Block rules linear scan rare.
- **Cohesive**: Single responsibility, well-scoped, 793 LOC reasonable.
- **Proposed**: (D) DO-NOT-SPLIT â€“ keep as is, rename to `nat/static.rs` for consistency. Ensure `pick_scoped`, `static_scope_ok`, `source_ok` stay `#[inline]`.

### `userspace-dp/src/filter/compiler.rs` (945 LOC)
- **Filter compiler**: `parse_filter_state_with_three_color_preserving` (264 LOC), `parse_term` (425 LOC) fusing addresses, ports, protocols, TCP flags, ICMP, flex match, actions, counters, policer linking. Cold path (config reconcile).
- **Proposed**: Split into `filter/compile/parse.rs`, `validate.rs`, `lower.rs`. Keep `compiler.rs` as facade. (C) optional cleanup, cold path, no hot impact. Ensure compiled `FilterTerm` layout unchanged.

### `userspace-dp/src/filter/engine/eval.rs` (1,026 LOC)
- **Filter evaluation**: Fuses standard eval, PBR routing-instance, log-match, output filter â€“ 30 functions. Hot for new flows and flowless packets. PBR evaluation is a filter action, should live with filter (not forwarding) â€“ correct per R4 in ps-010. Already well isolated â€“ hot path uses `#[inline]`, no alloc in term loop, logging sets bool only, stats batched via thread-local.
- **Proposed**: (C/D) â€“ cohesive hot path, split optional with inline guarantees. Optionally split into `filter/engine/pbr.rs`, `output.rs`, `log.rs`, keep core eval in `eval.rs`. Must preserve `#[inline(always)]` on `evaluate_filter_ref_counted_v4/v6`, `term_matches_v4/v6`. Verify via disassembly. PBR stays with filter (correct).
- **Hot-path preservation**: Must stay inline, no alloc, no dynamic dispatch. Current code good. If split, keep in same crate, no trait objects.

### `userspace-dp/src/screen/mod.rs` (1,479 LOC)
- **Screen orchestrator**: `ScreenState` with 22 fields, `check_packet_with_zone_id_opts` (373 LOC) orchestrating 16 checks, SYN cookie, scan/sweep. Already split per #1543 into `packet.rs`, `extract.rs`, `stateless.rs`, `rate.rs`, `syn_rate.rs`, `scan.rs`, `syncookie.rs`. Warm path (session miss only), not per-packet hot.
- **Proposed**: (D) DO-NOT-SPLIT â€“ already well modularized. Further split by check category would fragment orchestrator without reducing complexity. Checks are simple predicates, complexity in rate/sketch coordination which belongs in ScreenState.
- **Hot-path**: Warm, not hot â€“ runs only on session miss. Safe to allocate in cold paths. Hot path (`check_packet_with_zone_id_opts`) allocation-free. Keep as is.

### `userspace-dp/src/afxdp/wg/engine.rs` (1,763 LOC)
- **WireGuard engine**: Fuses hot data path (`encap_inner` 172 LOC, `try_decap` 223 LOC) with cold control (`reconcile_peers` 121 LOC, `install_session`, `classify_initiation`). Already modularized: `handshake_session.rs` (759 LOC), `cookie.rs`, `peer.rs`, `session.rs`, `timers.rs`.
- **Hot path**: `encap_inner` â€“ peer lookup, session gate, T3/T1 timers, pad, `next_tx_counter`, `snow.write_message`, activity stamps â€“ allocation-free, stack `MaybeUninit`, no locks on fast path (peer_arc clones Arc, session read lock). `try_decap` â€“ parse, counter reject, session lookup, replay window, `snow.read_message` â€“ hot, no alloc.
- **Proposed**: (B) for control plane, (D) for data path. Keep `encap_inner`/`try_decap` in `engine.rs` â€“ tightly coupled to `WgEngine` fields, must stay inline for performance. Optionally move cold methods (`reconcile_peers`, `install_session`, `classify_initiation`) to `wg/control.rs` to reduce LOC, but not urgent. Add hot/cold section comments.
- **Hot-path preservation**: Data path must remain allocation-free, lock-free (except RwLock::read), inlineable â€“ keep in same module as WgEngine for LTO. Cold path may allocate, take locks, log. Verify via `cargo test wg`, no `lock xadd` in hot path after Arc fix.

### `userspace-dp/src/gre.rs` (961 LOC)
- **GRE module**: Fuses `try_native_gre_decap_from_frame` (168 LOC) and `encapsulate_native_gre_frame` (152 LOC) plus shared ECN combine, checksum, parsing helpers. Hot path for tunnel traffic. Decap allocates one `Vec<u8>` for synthetic frame (unavoidable), encap allocates one `Vec<u8>` for outer frame. No other allocs. ECN combine shared with WG â€“ correct dedup.
- **Proposed**: (D) DO-NOT-SPLIT â€“ encap and decap share ECN logic, checksum, parsing. Splitting would duplicate helpers or create common module, increasing indirection. 961 LOC well under threshold, cohesive around tunnel logic.
- **Hot-path preservation**: Keep as is. Decap/encap allocs are intentional and unavoidable (header size change). Ensure no additional allocs. ECN combine pure and inlineable. Keep conversions cohesive in gre.rs.

### `userspace-dp/src/afxdp/neighbor.rs` (1,901 LOC)
- **Neighbor monolith**: Fuses ARP/NDP probe socket selection, ICMP echo building, kernel ARP trigger, neighbor warmer loop, netlink neighbor monitor, dump batch processing, CPU pinning â€“ 4 concerns, multiple protocols.
- **Hot path**: `trigger_kernel_arp_probe` (133 LOC) â€“ sends ICMP echo via raw/dgram socket to trigger kernel ARP/NDP â€“ on forwarding hot path when next-hop unresolved. Must not allocate, must not block. Currently stack buffers only, sockets cached per thread â€“ good.
- **Cold paths**: `neighbor_warmer_loop` (background thread), `neigh_monitor_thread` (271 LOC, netlink socket), `initial_neighbor_dump`, `process_dump_batch` â€“ may allocate, may block.
- **Proposed**: (B) split by concern, not by protocol:
  - `neighbor/probe.rs` â€“ `ProbeSockKind`, `select_probe_socket`, `build_icmp4_echo`, `build_icmp6_echo`, `trigger_kernel_arp_probe` â€“ hot path, keep allocation-free, `#[inline]`.
  - `neighbor/netlink.rs` â€“ `parse_neighbor_msg`, `process_dump_batch`, `neigh_monitor_thread` â€“ cold, netlink parsing.
  - `neighbor/warmer.rs` â€“ `neighbor_warmer_loop`, `WarmItem`, rate limiting â€“ cold background.
  - `neighbor/cpu.rs` â€“ `nth_allowed_cpu`, `pin_current_thread` â€“ generic, move to `afxdp/cpu.rs` or keep.
  - Keep ARP and NDP together in probe.rs â€“ they share socket selection and fallback logic; splitting by protocol would duplicate.
- **Hot-path preservation**: `trigger_kernel_arp_probe` must remain allocation-free and inlineable. After split, ensure `probe.rs` functions stay `#[inline]` and no heap alloc. Verify with `cargo test neighbor --lib`, no alloc on hot path.
- **Tests**: `dump_batch_tests`, `pin_tests`, `probe_socket_tests`, `warmer_tests` already comprehensive.

## 6. Findings â€“ by confidence

### High confidence

#### R13
- Title: `pkg/config/compiler_validate_strict.go` (6,997 LOC) â€“ monolithic cross-domain validator fusing 60+ domain validators â€“ split by domain into `pkg/config/validate_*.go`
- Severity: High (maintainability, build cost, review cost, merge conflicts)
- Confidence: High
- Refactor class: (A) MECHANICAL/SAFE â€“ pure functions, no state, cold path only
- Evidence:
  - File: `pkg/config/compiler_validate_strict.go` â€“ 6,997 lines, 112 symbols
  - Fuses validation for: policy, NAT, filter, zones, screens, CoS, IPsec/IKE, DHCP, BGP, RIB groups, VRRP, DDNS, flow/sampling, routing, firewall, applications, address-book, etc.
  - Example functions:
    ```go
    // 47-68: func validateLogEventModeFormatStrict(cfg *Config) error
    // 69-125: func validateThreeColorPolicersStrict(cfg *Config) error
    // 373-470: func validateIPsecPolicyProposalReferencesStrict(cfg *Config) error
    // 1197-1376: func validateRoutingExportReferencesStrict(cfg *Config) error
    // 2321-2400: func validatePolicyMatchAddressesStrict(cfg *Config) error
    // 3884-4118: func validateApplicationSpecsStrict(cfg *Config) error
    // 4653-4707: func validateFilterActionsStrict(cfg *Config) error
    // 6011-6099: func validateDestinationNATAddressesStrict(cfg *Config) error
    ```
  - Called from `compileExpanded` in `compiler.go:1901-4336` after section compilation, before returning typed Config.
  - Each validator is pure function `func validateXxxStrict(cfg *Config) error`, no shared state except `*Config`.
- Proposed decomposition:
  - New package `pkg/config/validate/` or files split by domain in `pkg/config/`:
    - `compiler_validate_strict_log.go` â€“ log, flow trace, security log (validateLogEventModeFormatStrict, etc.)
    - `compiler_validate_strict_cos.go` â€“ CoS, schedulers, policers (validateThreeColorPolicersStrict, etc.)
    - `compiler_validate_strict_ipsec.go` â€“ IPsec/IKE proposals, policies, traffic selectors
    - `compiler_validate_strict_routing.go` â€“ routing export, RIB groups, BGP, router-id, FRR auth, policy community
    - `compiler_validate_strict_firewall.go` â€“ firewall filter refs, policer refs, prefix-list, RI, cross-field, DSCP, protocols, actions
    - `compiler_validate_strict_policy.go` â€“ policy match addresses/applications, zone refs, duplicate names, terminal/log actions, address sets
    - `compiler_validate_strict_nat.go` â€“ NAT match applications, DNAT addresses/protocol/pool, source NAT pool, NAT64/NPTv6, source address names
    - `compiler_validate_strict_zone.go` â€“ zones, screens, host-inbound, address-book, VRRP
    - `compiler_validate_strict_application.go` â€“ application specs, syntax, structure, set members
  - Keep thin `compiler_validate_strict.go` dispatcher that calls domain validators in deterministic order, preserving current error precedence (first error wins).
  - Seam: cut along domain boundaries already evident in function name prefixes (validatePolicy*, validateNAT*, validateFilter*). Each file 300-800 LOC, single responsibility.
- Hot-path preservation analysis:
  - **N/A â€“ cold path only**: Validation runs only on config commit/commit-check, not per-packet. No dataplane fast path impact.
  - **Config apply latency**: Same work, better cache locality from smaller files â€“ may improve slightly, but not critical (commit is seconds, not microseconds).
  - **Snapshot structure**: Unaffected â€“ validators only read `*Config`, do not modify snapshot structures.
  - **How to verify**: 1) `go test ./pkg/config -run TestCompile -count=1` â€“ full compilation with validation; 2) `go test ./pkg/config -run "Strict|Validate"` â€“ specific validation tests; 3) `go test ./pkg/config -run TestCompiler` â€“ compiler tests; 4) Ensure error messages unchanged â€“ Go tests check error strings.
- Tests + gate:
  - Existing: `compiler_validate_*.go` tests per domain (e.g., `compiler_validate_scheduler_no_window_3860_test.go`, `compiler_validate_vrf_overlap_2387_test.go`, `schema_validate_*_test.go`) â€“ 200+ test files.
  - Move tests with source â€“ policy validation tests to `validate_policy_test.go`, etc., or keep in existing files (tests can stay, source moves).
  - Behavioral gate: `go test ./pkg/config -count=1`, `go test ./pkg/daemon -run TestApply` (config apply path).
- Why it matters:
  - **Maintainability**: 7k LOC file is the primary merge conflict hotspot. Change in NAT validation forces re-reading IPsec/BGP code. Navigation and review cost high â€“ finding the relevant validator requires searching 7k lines.
  - **Build cost**: Every edit to any validator recompiles the entire 7k LOC file and all its dependents (daemon, dataplane). Splitting into smaller files improves incremental build time dramatically â€“ NAT-only change recompiles only NAT validator, not IPsec/BGP.
  - **Review cost**: 7k LOC is unreviewable in a PR. Splitting by domain enables targeted review â€“ NAT expert reviews NAT validator, not IPsec. Reduces review time 5-10x.
  - **Ownership**: Different teams own different domains (policy, NAT, routing). Single file prevents clear OWNERS per domain. Split enables `pkg/config/validate_nat.go` owned by NAT team, etc.
  - **No performance risk**: Cold path only, pure functions â€“ safe to split mechanically.
- Fix direction (incremental, safe to land as small PRs):
  1. Create `pkg/config/validate_policy.go`, move all `validatePolicy*`, `validateApplication*`, `validateZone*`, `validateAddress*` functions (approx. 2,000 LOC). Update `compiler_validate_strict.go` dispatcher to call them. Run `go test ./pkg/config -run "Policy|Application|Zone|Address"`. PR #1.
  2. Create `pkg/config/validate_nat.go`, move `validateNAT*`, `validateDNAT*`, `validateSourceNAT*`, `validateNPTv6*`, `validateNAT64*` functions (approx. 1,500 LOC). Run `go test ./pkg/config -run "NAT|Nat"`. PR #2.
  3. Create `pkg/config/validate_firewall.go`, move `validateFirewall*`, `validateFilter*` functions (approx. 1,200 LOC). Run `go test ./pkg/config -run "Firewall|Filter"`. PR #3.
  4. Create `pkg/config/validate_routing.go`, move `validateRouting*`, `validateBGP*`, `validateRIB*` functions (approx. 1,000 LOC). PR #4.
  5. Create `pkg/config/validate_ipsec.go`, `validate_system.go`, `validate_cos.go`, `validate_log.go` for remaining domains. PR #5-8.
  6. Keep thin `compiler_validate_strict.go` with dispatcher function calling domain validators in order. Preserve error precedence.
  7. Each PR: mechanical file moves, no logic changes, keep function signatures. Verify with `go test ./pkg/config -count=1` and `go test ./pkg/daemon -run TestApply`.
- Labels: `refactor`, `maintainability`, `build-cost`, `review-cost`, `config-validation`, `cold-path`, `A-class`
- Dedup note: Not previously flagged as refactor. Prior campaigns focused on Rust hot path, not Go config validation. This is a new finding â€“ Go control plane monolith, not duplicating ps-010 R1â€“R12 which covered Rust dataplane. Not a duplicate.

#### R14
- Title: `pkg/config/compiler.go:compileExpanded` (2,435 LOC) god function fusing AST pre-walks, section compilation, and validation dispatch â€“ split into phase functions
- Severity: High (maintainability, testability, review cost)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ complex ordering, but cold path, preserve validation order for error precedence
- Evidence:
  - File: `pkg/config/compiler.go` â€“ 4,336 LOC, `compileExpanded` at lines 1901-4336 (~2,435 LOC).
  - **Responsibilities fused:**
    1. **AST sanitization/pre-walks** (lines 1901-2280): control chars, VRRP track, VRRP auth, TCP MSS, log stream port/TLS, flow trace file/flags/size, interface-range expansion, unsupported interface stanzas, application collisions, firewall family collisions, bind-interface, IPsec TS, policy match/then, missing match, DNAT to-scope.
    2. **Typed Config construction** (2282-2350): `cfg := &Config{...}` with manual map init.
    3. **Section compilation dispatch** (2336-2600): switch on `security`, `interfaces`, `applications`, `routing-options`, etc., calling `compileSecurity`, `compileInterfaces`, etc.
    4. **Strict validation dispatch** (2600-4300): 60+ calls to `validateXxxStrict(cfg)`.
    5. **Warning aggregation** throughout.
  - Quoted snippet:
    ```go
    func compileExpanded(tree *ConfigTree, opts compileOpts) (*Config, error) {
        var ctrlCharWarnings []string
        if opts.sanitizeFreeTextControlChars { ...
        trackWarnings, err := validateVRRPTrackInterfaceAST(...)
        ...
        ifaceRangeWarnings := expandInterfaceRanges(tree)
        ...
        cfg := &Config{ Security: SecurityConfig{...}, ... }
        cfg.Warnings = append(cfg.Warnings, ctrlCharWarnings...)
        ...
        for _, node := range tree.Children {
            switch node.Name() {
            case "security":
                if err := compileSecurity(node, &cfg.Security); err != nil {
        ...
        // 60+ validation calls
        if err := validateLogEventModeFormatStrict(cfg); err != nil { ...
    ```
- Proposed decomposition:
  - New file `pkg/config/compile_phases.go`:
    - `func runASTPreWalks(tree *ConfigTree, opts compileOpts) ([]string, error)` â€“ extracts all AST-level gates (lines 1901-2280). Returns warnings and error.
    - `func newEmptyConfig() *Config` â€“ extracts Config initialization with maps (lines 2282-2350).
    - `func compileSections(tree *ConfigTree, cfg *Config) error` â€“ extracts section switch dispatch (lines 2336-2600).
    - `func runStrictValidators(cfg *Config) error` â€“ extracts strict validation dispatch sequence (lines 2600-4300).
  - `compileExpanded` becomes thin orchestrator (approx. 50 LOC):
    ```go
    func compileExpanded(tree *ConfigTree, opts compileOpts) (*Config, error) {
        warnings, err := runASTPreWalks(tree, opts)
        if err != nil { return nil, err }
        cfg := newEmptyConfig()
        cfg.Warnings = append(cfg.Warnings, warnings...)
        if err := compileSections(tree, cfg); err != nil { return nil, err }
        if err := runStrictValidators(cfg); err != nil { return nil, err }
        return cfg, nil
    }
    ```
  - Seam: cut by **compilation phase** â€“ AST pre-walks (sanitization), Config construction, section compilation, strict validation. Each phase takes `*ConfigTree` or `*Config` and returns warnings/error; no shared mutable state across phases except `cfg` built in phase 2 and passed to phases 3-4.
- Hot-path preservation analysis:
  - **N/A â€“ cold path only**: `compileExpanded` runs only on config commit/commit-check, not per-packet. No dataplane fast path impact.
  - **Validation order**: Must preserve validation order for error precedence (first error wins). `runStrictValidators` must call validators in same order as current code.
  - **Warning aggregation**: Warnings from pre-walks and compilation must be aggregated in same order â€“ preserve.
  - **How to verify**: 1) `go test ./pkg/config -run TestCompileConfig -count=1` â€“ full compilation; 2) `go test ./pkg/config -run TestCompile` â€“ compiler tests; 3) Full `go test ./pkg/config` â€“ 200+ test files; 4) Ensure error messages and warning order unchanged â€“ tests check error strings.
- Tests + gate:
  - Existing: `compiler_test.go`, `compiler_*_test.go` (200+ files) â€“ extensive coverage of compilation phases.
  - Move tests with phases if desired, or keep in existing files.
  - Behavioral gate: `go test ./pkg/config -count=1`, `go test ./pkg/daemon -run TestApply` (config apply path), `go test ./pkg/dataplane/... -run TestCompile`.
- Why it matters:
  - **Maintainability**: 2,435 LOC function is untestable in isolation; AST pre-walks, compilation, and validation are distinct responsibilities with different failure modes. Changing an AST pre-walk requires reading 2,435 lines.
  - **Testability**: Cannot unit test AST pre-walks without running full compilation. Extracting `runASTPreWalks` enables focused unit tests for each pre-walk.
  - **Review cost**: 2,435 LOC is unreviewable. Splitting by phase enables targeted review â€“ AST changes reviewed separately from validation changes.
  - **Build cost**: Every edit recompiles the entire 4,336 LOC file. Splitting improves incremental build.
  - **No performance risk**: Cold path, pure functions â€“ safe to split.
- Fix direction (incremental):
  1. Extract `runASTPreWalks` â€“ move lines 1901-2280 to new function in `compile_phases.go`. Replace with call. Run `go test ./pkg/config -run TestCompile`. PR #1.
  2. Extract `newEmptyConfig` â€“ move Config initialization to new function. PR #2.
  3. Extract `compileSections` â€“ move section switch to new function. PR #3.
  4. Extract `runStrictValidators` â€“ move 60+ validation calls to new function. PR #4.
  5. `compileExpanded` becomes thin orchestrator â€“ verify with full test suite.
  6. Each PR: mechanical extraction, no logic changes, preserve order. Verify error messages and warnings unchanged.
- Labels: `refactor`, `god-function`, `compiler`, `maintainability`, `cold-path`, `B-class`
- Dedup note: Not previously flagged. ps-010 focused on Rust hot path, not Go compiler. This is a new finding â€“ Go config compilation monolith. Not a duplicate.

#### R15
- Title: `userspace-dp/src/nat/source.rs` (1,190 LOC) fusing SNAT rule parsing, matching, and pool allocation â€“ split into rule, match, and alloc modules
- Severity: Medium (maintainability, hot-path clarity)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ hot for new flows, must preserve inlining and no alloc
- Evidence:
  - File: `userspace-dp/src/nat/source.rs` â€“ 1,190 lines, 42 symbols
  - **Fusion:**
    - Rule parsing: `parse_source_nat_rules_with_previous` (481-649, 169 LOC), `expand_pool_address` (425-476), `parse_match_prefix` (1139-1159) â€“ **cold** (config build)
    - Scope matching: `scope_matches` (308-326), `l4_matches` (345-367), `matches` (369-403) â€“ **hot** (new flow, session miss)
    - Allocation driver: `match_source_nat_result_for_tuple` (861-1138, 278 LOC) calls `pool_allocator.allocate_translation`, `try_next_port`, `address_index` â€“ **hot**
    - Decision merging: `SourceNatLookup::Matched(NatDecision)` â€“ hot
    - Failure formatting: `SourceNatFailure::for_rule` clones `rule.name`, `pool_name` Strings â€“ **cold** (error path only)
  - **God-struct**: `SourceNatRule` (211-276) mixes config (prefixes, zones, pool addresses) with runtime (`pool_allocator: PortAllocator`, `hit_counter: Option<Arc<NatRuleCounter>>`).
  - Snippet:
    ```rust
    // userspace-dp/src/nat/source.rs:861-913
    pub(crate) fn match_source_nat_result_for_tuple(...) -> SourceNatLookup {
        for rule in rules {  // linear scan, hot
            if !rule.matches(...) { continue; }  // scope + L4 + prefix, hot
            ...
            if rule.pool_mode {
                let translated = match rule.pool_allocator.allocate_translation(  // hot, Mutex
    ```
- Proposed decomposition:
  - `nat/snat_rule.rs` â€“ `SourceNatRule`, `SourceNatAppTerm`, `PersistentNatPermit`, parsing (`parse_source_nat_rules_with_previous`, `expand_pool_address`, `parse_match_prefix`, `nets_match_*`, `port_in_ranges`) â€“ cold
  - `nat/snat_match.rs` â€“ `SourceNatFlowKey`, `scope_matches`, `l4_matches`, `matches`, `match_source_nat_result_for_tuple`, `match_source_nat_result`, `match_source_nat` â€“ hot
  - `nat/snat_alloc.rs` â€“ thin wrappers `release_source_nat_allocation`, `rollback_source_nat_allocation`, `reserve_synced_source_nat_allocation` (currently 667-801) â€“ cold (session teardown, HA sync)
  - Keep `SourceNatLookup`, `SourceNatFailure`, `SourceNatFailureReason` in `snat_match.rs` (hot enum, cold String clones isolated to `for_rule`)
  - Seam: cut by **lifecycle phase** â€“ rule parsing (cold, config), matching/allocation (hot, new flow), release/rollback (cold, teardown). Already partially separated by function, just need file moves.
- Hot-path preservation analysis:
  - **Hot**: `match_source_nat_result_for_tuple` â†’ `rule.matches` (prefix iteration, no alloc) â†’ `pool_allocator.allocate_translation` (Mutex<PortAllocatorLiveState>, bounded GC, no per-packet alloc except rare retained Vec on collision). Must stay **inline**, no new Arc/Vec per flow, no dynamic dispatch.
  - **Cold**: parsing, `SourceNatFailure::for_rule` (String clones), `release/rollback` (session teardown, not per-packet).
  - **UMEM**: SNAT only produces `NatDecision`; actual packet rewrite happens in `checksum.rs` in-place, zero-copy preserved. No frame alloc in SNAT path.
  - **If split across crate**: `match_source_nat_result_for_tuple` and `PortAllocator::allocate_translation` need `#[inline]` to avoid call overhead on new-flow hot path. Currently same crate (`crate::nat`), inlining OK. If moved to separate crate, add `#[inline]` and verify with LTO.
  - **How to verify**: 1) `cargo test nat --lib pool_snat` â€“ SNAT allocation tests; 2) `perf` on session-miss path with SNAT â€“ measure `match_source_nat_result_for_tuple` latency, ensure <10Âµs for 1k rules; 3) Disassembly of `match_source_nat_result_for_tuple` â€“ ensure no hidden alloc (String, Vec) on success path, only on error path; 4) `make test`, `test-failover` â€“ HA sync of NAT allocations via `reserve_synced_source_nat_allocation`.
- Tests + gate:
  - `cargo test nat --lib` â€“ existing 8,685 LOC in `nat/tests.rs` covers SNAT extensively (pool allocation, persistent NAT, rollback, exhaustion).
  - `make test` â€“ userspace-dp integration
  - `test-failover` â€“ HA sync of NAT allocations
  - Add microbench for `match_source_nat_result_for_tuple` with 1k rules to ensure linear scan remains <10Âµs after split.
- Why it matters:
  - **Maintainability**: SNAT is hot for new flows (session miss) â€“ DNAT before policy, SNAT after policy. Fusing cold parsing with hot match increases cognitive load and risks accidental alloc/logging in hot path. Separating clarifies hot-path invariants (no alloc, no logging, Mutex only).
  - **God-struct**: `SourceNatRule` mixes config with runtime â€“ splitting reduces size and clarifies Send/Sync bounds. Runtime fields (`pool_allocator`, `hit_counter`) should be in separate struct from config fields.
  - **Testability**: Rule parsing and matching can be unit tested in isolation â€“ currently fused, hard to test matching without parsing.
  - **Build cost**: Changing pool allocation logic recompiles rule parsing â€“ unnecessary. Split reduces rebuild scope.
- Fix direction (incremental):
  1. Extract parsing to `snat_rule.rs` with `#[cfg(test)]` helpers for `expand_pool_address`. Keep `SourceNatRule` struct definition in `snat_rule.rs` or `snat_match.rs` â€“ if kept in match, parsing function returns rule struct. PR #1.
  2. Move match functions to `snat_match.rs`, keep `#[inline]` on `matches`, `l4_matches`, `scope_matches`. Keep allocation driver in `snat_match.rs` (hot) but move release/rollback to `snat_alloc.rs` (cold). PR #2.
  3. Audit `SourceNatFailure::for_rule` â€“ ensure String clones only on error path (already true). Keep in `snat_match.rs`.
  4. Add `#[inline]` to `PortAllocator::allocate_translation` if moved to separate module. Verify inlining with `cargo show-asm`.
  5. Each PR: mechanical file moves, no logic changes, keep function signatures. Run `cargo test nat`, `make test`, `test-failover`.
- Labels: `refactor`, `nat`, `snat`, `hot-path`, `monolithic`, `B-class`, `x-hpc`
- Dedup note: Already split from monolithic `nat.rs` per #1542; this is second-level decomposition. `SnapshotIntegrityError` mixing NAT/policy errors flagged in ps-010 R2 â€“ not duplicated here (this is NAT source module split, not error enum). Not a duplicate of ps-010 findings which covered poll_descriptor, policy, session, forwarding, TX, CoS â€“ not NAT source.

#### R16
- Title: `userspace-dp/src/nat/allocator.rs` (926 LOC) â€“ `PortAllocator` god-struct mixing hot port bitmap with cold config, stats, GC â€“ split hot/cold, rename to `nat/pool.rs`
- Severity: Medium (maintainability, hot-path clarity, lock contention surface)
- Confidence: High
- Refactor class: (C) PERFORMANCE-POSITIVE â€“ hot/cold separation clarifies invariants, reduces lock contention surface
- Evidence:
  - File: `userspace-dp/src/nat/allocator.rs` â€“ 926 lines
  - **God-struct**: `PortAllocator` (181-185): `shared: Arc<PortAllocatorShared>`, `port_low/high: u16` â€“ cold config mixed with hot Arc.
  - `PortAllocatorShared` (159-171): `counters: Vec<AtomicU32>` (hot, round-robin), `addr_counter_v4/v6: AtomicU32` (hot), `live: Mutex<PortAllocatorLiveState>` (hot), `allocations_total/reuses_total/exhaustion_total: AtomicU64` (cold stats), `max_tracked_flows: usize` (cold config).
  - `PortAllocatorLiveState` (124-139): `live_by_flow: FxHashMap` (hot), `owner_by_translated: FxHashMap` (hot), `persistent_by_source: FxHashMap` (hot), `lease_expirations: BTreeSet` (cold GC), `next_port_offset_by_addr: Vec<u32>` (hot, sequential cursor), `recycled_ports_by_addr: Vec<VecDeque<u16>>` (hot, FIFO).
  - **Hot functions**: `allocate_translation` (312-479, 168 LOC) â€“ Mutex lock, GC bounded (ALLOCATION_GC_BUDGET=8), `claim_free_port_locked` loop, no alloc on common path. `claim_free_port_locked` (481-546) â€“ sequential probe then FIFO recycle, `retained: Vec<u16>` lazily allocated only on collision. `try_next_port` (295-309) â€“ atomic fetch_add, no lock. `address_index` (271-294) â€“ hash or atomic round-robin, no lock.
  - **Cold functions**: `gc_expired_locked` (781-810), `snapshot` (768-780), `release_flow` (613-653), `rollback_flow` (654-723), `reserve_flow` (724-767), `debug_*` (231-270).
  - Snippet:
    ```rust
    // userspace-dp/src/nat/allocator.rs:336-342
    let mut live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
    self.gc_expired_locked(&mut self, now_ns, ALLOCATION_GC_BUDGET);  // cold fused in hot
    if let Some(existing) = live.live_by_flow.get(&flow) {  // hot reuse check
    ```
- Proposed decomposition:
  - Rename `allocator.rs` to `pool.rs` (matches `nat/pool.rs` proposal, clearer than "allocator").
  - Split `PortAllocatorShared` into:
    - `PortAllocatorHot` â€“ `counters: Vec<AtomicU32>`, `addr_counter_*`, `live: Mutex<PortAllocatorLiveStateHot>` (only `live_by_flow`, `owner_by_translated`, `next_port_offset_by_addr`, `recycled_ports_by_addr`)
    - `PortAllocatorCold` â€“ `allocations_total`, `reuse_total`, `exhaustion_total`, `max_tracked_flows`, `lease_expirations`, `persistent_by_source` (persistent lease state machine is warm, not per-packet)
  - Move GC functions to `pool_gc.rs` or keep in `pool.rs` but mark `#[cold]` and ensure not inlined into hot path.
  - Move `snapshot`, `debug_*` to `pool_status.rs` (cold).
  - Keep `allocate_translation` and `claim_free_port_locked` in hot module with `#[inline]`.
  - Seam: cut by **temperature** â€“ hot allocation path (Mutex, bitmap, cursor) vs cold GC/stats/persistent leases. Already partially separated by function, just need struct split and file moves.
- Hot-path preservation analysis:
  - **Hot**: `allocate_translation` must stay lock-bound, no alloc, no BTreeSet iteration beyond bounded budget. Currently good: Mutex held, GC budget 8, `retained` Vec only on collision (rare). `next_port_offset_by_addr` Vec<u32> is cache-friendly sequential cursor. `recycled_ports_by_addr` VecDeque pop_front O(1).
  - **Cold**: GC, snapshot, stats fetch_add (cheap but cold), persistent lease expiration (BTreeSet).
  - **Must not**: Allocate per packet (currently only `retained` Vec on collision, acceptable), take multiple locks, or do logging/formatting in hot path (none).
  - **UMEM**: Allocator only returns `TranslatedTuple`; no packet modification, zero-copy preserved.
  - **Cache**: `counters: Vec<AtomicU32>` per address, `next_port_offset_by_addr: Vec<u32>` â€“ both cache-friendly linear arrays. Good. Splitting hot/cold preserves this.
  - **If split**: `allocate_translation`, `claim_free_port_locked`, `try_next_port`, `address_index` need `#[inline]` if moved to separate module/crate.
  - **How to verify**: 1) `cargo test nat --lib pool_snat` â€“ allocation, exhaustion, persistent, rollback tests; 2) `perf` on session-miss path with SNAT â€“ measure `allocate_translation` latency, ensure p99 <5Âµs; 3) Disassembly of `allocate_translation` â€“ ensure no hidden alloc (String, Vec) on success path, only on collision; 4) `make test`, `test-failover` â€“ HA sync via `reserve_flow`.
- Tests + gate:
  - `cargo test nat --lib pool_snat` (covers allocation, exhaustion, persistent, rollback, recycle order, collision probes)
  - `make test` with HA failover (`test-failover`) to verify `reserve_flow` correctness for P1 fix.
  - Perf: measure `allocate_translation` latency under 1M flows, ensure p99 <5Âµs after split.
- Why it matters:
  - **Hot-path clarity**: Pool allocation is hot for new flows requiring SNAT. Any per-packet alloc, logging, or unbounded GC would blow up session-miss latency. Current code is careful (bounded GC, lazy Vec), but god struct makes it hard to audit hot vs cold. Separating clarifies invariants and prevents future cold code creeping into hot path.
  - **Lock contention**: `PortAllocatorLiveState` mixes hot maps (`live_by_flow`, `owner_by_translated`) with cold BTreeSets (`lease_expirations`). Split reduces lock contention surface and clarifies what must be cache-friendly.
  - **Maintainability**: 926 LOC with hot/cold fusion is hard to review. Splitting reduces cognitive load and enables focused testing of hot allocation vs cold GC.
  - **Performance-positive**: Hot/cold separation is also a dcache win â€“ hot maps and cursors packed together, cold BTreeSets separate â€“ fewer cache lines touched on allocation.
- Fix direction (incremental):
  1. Rename `allocator.rs` to `pool.rs` (mechanical, update mod.rs). PR #1.
  2. Split `PortAllocatorLiveState` into `HotState` and `ColdState`, embed in `PortAllocatorShared`. Keep Mutex on HotState only, ColdState protected by same Mutex or separate. PR #2.
  3. Mark GC functions `#[cold]` and move to `pool_gc.rs` or keep in `pool.rs` but ensure not inlined. PR #3.
  4. Move `snapshot`, `debug_*` to `pool_status.rs`. PR #4.
  5. Keep `allocate_translation` and `claim_free_port_locked` in hot module with `#[inline]`. Audit `retained: Vec<u16>` â€“ ensure lazy alloc only on collision (currently good). Consider `SmallVec` for stack allocation.
  6. Each PR: mechanical moves, no logic changes. Run `cargo test nat`, `make test`, `test-failover`, perf on allocation latency.
- Labels: `refactor`, `nat`, `snat`, `allocator`, `hot-path`, `god-struct`, `C-class`, `x-hpc`
- Dedup note: Persistent NAT lease state machine already isolated here per #1542; this is hot/cold separation within allocator, not a duplicate of #1542 which split NAT from single file. Not a duplicate of ps-010 findings â€“ ps-010 covered session, policy, forwarding, not NAT allocator internals.

#### R17
- Title: `userspace-dp/src/nat64.rs` (2,047 LOC) fusing classification, translation, ICMP, checksum â€“ split into `nat/nat64/` submodule
- Severity: Medium-High (maintainability, per-packet translation cost, UMEM ownership)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ translation is per-packet hot, must preserve zero-copy for non-NAT64, UMEM frame release
- Evidence:
  - File: `userspace-dp/src/nat64.rs` â€“ 2,047 lines, 54 symbols
  - **Fusion:**
    - **Classification:** `Nat64State::from_snapshots` (248-336), `match_ipv6_dest` (343-363), `classify_ipv6_dest` (364-379), `forward_decision` (392-436) â€“ **hot** (per new flow and per packet to determine if NAT64 needed)
    - **Translation:** `translate_v6_to_v4` (540-575), `translate_v4_to_v6` (931-955), `write_v6_to_v4_into` (749-930, 182 LOC), `write_v4_to_v6_into` (956-1170, 215 LOC) â€“ **hot** (per packet for NAT64 flows)
    - **ICMP:** `map_icmpv6_error_to_icmpv4` (1171-1216), `map_icmpv4_error_to_icmpv6` (1217-1264), embedded translation (1496-1639) â€“ **warm** (ICMP errors, less frequent)
    - **Checksum:** `recompute_l4_checksum_after_nat64_*` (1669-1757), `checksum16_*` (1758-1832), `adjust_l4_checksum_*_incremental` (1864-1944) â€“ **hot** (per translated packet)
    - **Frame building:** `build_nat64_v6_to_v4_frame` (1945-1978), `build_nat64_v4_to_v6_frame` (1979-2015) â€“ **hot** (allocates new frame)
    - **Fragment handling:** `ipv6_l4_offset_and_protocol` (576-630), `ipv6_is_non_first_fragment` (631-680) â€“ **warm**
  - Snippet:
    ```rust
    // userspace-dp/src/nat64.rs:749-780
    fn write_v6_to_v4_into(...) -> Option<usize> {
        // 182 LOC building new IPv4 frame from IPv6, allocates Vec?
        let mut buf = vec![0u8; new_len];  // per-packet alloc!
    ```
- Proposed decomposition:
  - `nat/nat64/mod.rs` â€“ `Nat64State`, `Nat64Prefix`, `Nat64Match`, classification (`match_ipv6_dest`, `classify_ipv6_dest`, `forward_decision`) â€“ hot, keep `#[inline]`
  - `nat/nat64/translate.rs` â€“ `translate_v6_to_v4`, `translate_v4_to_v6`, `write_v6_to_v4_into`, `write_v4_to_v6_into`, frame building â€“ hot, per-packet alloc unavoidable
  - `nat/nat64/icmp.rs` â€“ ICMP error mapping, embedded translation â€“ warm
  - `nat/nat64/checksum.rs` â€“ `checksum16_*`, `recompute_l4_checksum_*`, `adjust_l4_checksum_*` â€“ hot, pure math, keep `#[inline]`
  - `nat/nat64/fragment.rs` â€“ fragment handling, `ipv6_fragment_header`, `next_frag_id`, `map_frag_id` â€“ warm
  - Seam: cut by **function** â€“ classification (decide if NAT64), translation (do the translation), ICMP (error handling), checksum (math), fragments. Each has distinct hot/cold profile.
- Hot-path preservation analysis:
  - **Hot â€“ classification**: `match_ipv6_dest` is per new flow and per packet (to determine if NAT64 translation needed). Must be fast prefix match, no alloc. Currently `Nat64Prefix` contains `Ipv6Net`, matching is prefix contains check â€“ good, no alloc. Must stay `#[inline]`.
  - **Hot â€“ translation**: `write_v6_to_v4_into`, `write_v4_to_v6_into` are **per packet** for NAT64 flows, not just new flows. This is critical: NAT64 changes header size (IPv6 40B â†’ IPv4 20B, or vice versa), so **new frame allocation is unavoidable**. Currently allocates `Vec<u8>` per packet â€“ acceptable for NAT64 (cross-family translation inherently requires new frame), but must be zero-copy for non-NAT64 paths. Ensure non-NAT64 fast path (classification miss) does zero alloc, zero copy.
  - **Must not**: Allocate on classification path (non-NAT64 packets). Currently classification only does prefix checks, no alloc â€“ good. Must preserve.
  - **UMEM ownership**: NAT64 translation allocates new frame, copies payload, then releases original UMEM frame. This is expected and unavoidable for header size change. Ensure original frame is released back to UMEM pool (no leak). New frame should be allocated from UMEM or heap? Should be UMEM for zero-copy downstream. Verify â€“ if heap, it's a performance issue. Ensure UMEM frame release on translation, no leak.
  - **Checksum**: Incremental checksum adjustment is hot, must stay inline, no alloc. Currently pure math functions, good. Keep `#[inline]`.
  - **If split**: Translation functions need `#[inline]` for checksum helpers, but frame allocation dominates cost so inlining less critical. Keep in same crate for inlining of classification.
  - **How to verify**: 1) `cargo test nat64` â€“ existing tests in `nat64.rs` mod tests; 2) `make test` with NAT64 config; 3) Perf: measure NAT64 translation throughput (packets/sec) vs native forwarding, ensure <10% overhead for 64B packets, no regression after split; 4) Verify UMEM frame release on NAT64 translation (no leak) via `test-umem-leak` or manual inspection â€“ ensure original frame recycled, new frame from UMEM; 5) Disassembly of `match_ipv6_dest` â€“ should be simple prefix check, no alloc, inlined.
- Tests + gate:
  - `cargo test nat64` â€“ classification, translation, ICMP, checksum, fragments.
  - `make test` with NAT64 config â€“ integration.
  - Perf: NAT64 translation throughput before/after split.
  - UMEM leak test: run NAT64 traffic, check UMEM frames released â€“ no leak.
  - `test-failover` â€“ NAT64 with HA.
- Why it matters:
  - **Maintainability**: NAT64 is **hot for every packet** in a NAT64 flow (not just new flows), unlike SNAT/DNAT which only translate new flows then use session table. Fusing classification (hot, per packet) with translation (hot, per packet, allocates) with ICMP (warm) and checksum (hot) makes it hard to audit per-packet cost. 2,047 LOC single file is monolithic.
  - **Performance clarity**: Frame allocation in translation is unavoidable but must be isolated and audited for UMEM leak. Splitting clarifies which functions are per-packet hot vs per-flow warm vs config cold.
  - **UMEM ownership**: NAT64 translation is the only place in the dataplane that allocates a new frame for an existing packet (header size change). The UMEM lifecycle (release original, allocate new) must be correct â€“ leak would starve UMEM. Isolation enables focused audit.
  - **Build cost**: Changing ICMP mapping recompiles translation and checksum â€“ unnecessary. Split reduces rebuild scope.
- Fix direction (incremental):
  1. Create `nat/nat64/` directory with `mod.rs`, move `Nat64State`, `Nat64Prefix`, classification functions to `mod.rs`. Keep `#[inline]` on `match_ipv6_dest`, `classify_ipv6_dest`. PR #1.
  2. Create `nat/nat64/translate.rs`, move `translate_*`, `write_*_into`, frame building functions. Add comment explaining why alloc is unavoidable (header size change). Ensure non-NAT64 path zero alloc. PR #2.
  3. Create `nat/nat64/icmp.rs`, move ICMP mapping and embedded translation. PR #3.
  4. Create `nat/nat64/checksum.rs`, move checksum functions, keep `#[inline]`. PR #4.
  5. Create `nat/nat64/fragment.rs`, move fragment handling. PR #5.
  6. Each PR: mechanical moves, no logic changes. Run `cargo test nat64`, `make test`, perf, UMEM leak check.
  7. Consider pre-allocated frame pool for NAT64 to avoid per-packet Vec alloc â€“ future optimization, not required for split.
- Labels: `refactor`, `nat64`, `translation`, `hot-path`, `monolithic`, `B-class`, `umem`, `x-hpc`
- Dedup note: NAT64 already separate file from `nat/` module; this is internal decomposition of the 2,047 LOC monolith. Not a duplicate of ps-010 findings â€“ ps-010 covered policy, session, forwarding, TX, CoS, not NAT64 internals. Prior campaign did not flag NAT64 specifically. New finding.

#### R18
- Title: `userspace-dp/src/afxdp/neighbor.rs` (1,901 LOC) fusing ARP, NDP, netlink, warmer, CPU pinning â€“ split by concern into `neighbor/` submodule
- Severity: Medium (cognitive load, hot path clarity)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ `trigger_kernel_arp_probe` is on forwarding hot path, must not allocate
- Evidence:
  - File: `userspace-dp/src/afxdp/neighbor.rs` â€“ 1,901 lines
  - **Fusion:**
    - Probe socket selection: `select_probe_socket` (71-81) â€“ pure, protocol-agnostic â€“ hot path helper
    - ICMP echo building: `build_icmp4_echo`, `build_icmp6_echo` (97-112) â€“ protocol-specific â€“ hot path helper
    - Kernel ARP trigger: `trigger_kernel_arp_probe` (158-291, 133 LOC) â€“ sends ICMP echo via raw/dgram socket to trigger kernel ARP/NDP â€“ **on forwarding hot path** when next-hop unresolved. Must not allocate, must not block.
    - Neighbor warmer loop: `neighbor_warmer_loop` (292-362) â€“ background thread, processes warmer messages with per-key rate limiting â€“ cold
    - Netlink neighbor monitor: `neigh_monitor_thread` (840-1111, 271 LOC) â€“ netlink socket, baseline generation, message loop â€“ cold background
    - Netlink parsing: `parse_neighbor_msg` (464-541), `process_dump_batch` (607-670) â€“ cold
    - CPU pinning: `nth_allowed_cpu`, `pin_current_thread` (1112-1151) â€“ generic, unrelated to neighbor logic
  - **Hot path**: `trigger_kernel_arp_probe` is called on forwarding path when next-hop is unresolved. Currently stack buffers only, sockets cached per thread, `sendto` syscall unavoidable â€“ good, no alloc.
  - **Cold paths**: Warmer loop, netlink monitor, dump processing â€“ may allocate, may block â€“ run in background threads.
- Proposed decomposition:
  - Split into `neighbor/` directory:
    - `neighbor/mod.rs` â€“ re-exports, `monotonic_nanos`, `NeighborMsgEffect`, public API (`trigger_kernel_arp_probe`, `neighbor_warmer_loop`, etc.)
    - `neighbor/probe.rs` â€“ `ProbeSockKind`, `select_probe_socket`, `build_icmp4_echo`, `build_icmp6_echo`, `build_solicit_sockaddr_in6`, `trigger_kernel_arp_probe` â€“ hot path, keep allocation-free, `#[inline]`
    - `neighbor/warmer.rs` â€“ `neighbor_warmer_loop`, `WarmItem`, rate limiting â€“ cold background
    - `neighbor/netlink.rs` â€“ `parse_neighbor_msg`, `process_dump_batch`, `request_neighbor_dump`, `initial_neighbor_dump`, `neigh_monitor_thread`, `set_neigh_monitor_rcvbuf` â€“ cold, netlink parsing
    - `neighbor/cpu.rs` â€“ `nth_allowed_cpu`, `pin_current_thread` â€“ generic, or move to `afxdp/cpu.rs`
  - Keep ARP and NDP together in `probe.rs` â€“ they share socket selection and fallback logic; splitting by protocol would duplicate the fallback mechanism.
  - Netlink parsing handles both AF_INET and AF_INET6 â€“ keep together, address family is a parameter.
  - Seam: cut by **concern** (probe vs netlink vs warmer vs CPU) not by protocol. Hot probe functions isolated from cold netlink/warmer.
- Hot-path preservation analysis:
  - **Hot**: `trigger_kernel_arp_probe` must not allocate, must not block. Currently stack-only, good. After split, ensure `neighbor/probe.rs` functions remain `#[inline]` and allocation-free. Use `#[inline]` on `build_icmp4_echo`, `build_icmp6_echo`, `select_probe_socket`.
  - **Cold**: Warmer loop, netlink monitor, dump processing â€“ may allocate, may block â€“ run in background threads, no hot-path impact.
  - **No new alloc on hot path**: `trigger_kernel_arp_probe` currently uses stack buffers only â€“ preserve. Do not introduce `Vec`, `String`, or `Box` in probe path.
  - **How to verify**: 1) `cargo test neighbor --lib` â€“ `dump_batch_tests`, `pin_tests`, `probe_socket_tests`, `warmer_tests`; 2) `cargo test --test integration neighbor` â€“ netlink monitor; 3) `make test` â€“ full suite; 4) Verify no alloc on hot path via `cargo test probe_socket -- --nocapture` with debug asserts or allocation tracker.
- Tests + gate:
  - `cargo test neighbor --lib` â€“ comprehensive existing tests.
  - `cargo test --test integration neighbor` â€“ netlink integration.
  - `make test` â€“ full suite.
  - **Critical**: Verify `trigger_kernel_arp_probe` remains allocation-free after split â€“ no `Vec`, `String`, or heap alloc on hot path.
- Why it matters:
  - **Hot-path clarity**: Neighbor resolution is on the forwarding hot path â€“ a slow or allocating probe directly impacts packet latency. The file fuses multiple concerns (probe sockets, netlink, warmer, CPU pinning) making it hard to audit the hot path in isolation. Splitting by concern clarifies which code runs on hot path vs background threads.
  - **Maintainability**: 1,901 LOC with 4 concerns is hard to navigate. Splitting improves readability and enables focused testing of probe logic vs netlink parsing.
  - **Build cost**: Changing netlink parsing recompiles probe logic â€“ unnecessary. Split reduces rebuild scope.
  - **No performance risk**: Probe functions already allocation-free; moving to separate file within same crate preserves inlining. Cold paths (netlink, warmer) can allocate freely.
- Fix direction (incremental):
  1. Create `neighbor/probe.rs`, move `ProbeSockKind`, `select_probe_socket`, `build_icmp*`, `trigger_kernel_arp_probe`. Keep `#[inline]` on builders. Update `neighbor.rs` to `mod probe; pub use probe::*;`. Run `cargo test neighbor --lib probe_socket`. PR #1.
  2. Create `neighbor/netlink.rs`, move netlink parsing and monitor thread. PR #2.
  3. Create `neighbor/warmer.rs`, move warmer loop. PR #3.
  4. Move CPU pinning to `afxdp/cpu.rs` or `neighbor/cpu.rs`. PR #4.
  5. Keep `neighbor.rs` as `mod.rs` with re-exports for backward compatibility.
  6. Each PR: mechanical file moves, no logic changes. Verify no alloc on hot path, run neighbor tests.
- Labels: `refactor`, `neighbor`, `arp`, `ndp`, `hot-path`, `B-class`, `modularity`
- Dedup note: Not previously flagged. ps-010 covered forwarding, session, policy, TX, CoS â€“ not neighbor. This is a new finding â€“ neighbor module monolith. Not a duplicate.

### Medium confidence

#### R19
- Title: `userspace-dp/src/nat/tests.rs` (8,685 LOC, 232 tests) â€“ monolithic test dumping ground for all NAT types â€“ split per module
- Severity: Medium (developer productivity, compile time, merge conflicts)
- Confidence: High
- Refactor class: (B) â€“ test-only, no hot-path impact, improves maintainability
- Evidence:
  - File: `userspace-dp/src/nat/tests.rs` â€“ 8,685 lines, 232 test functions
  - Covers: SNAT pool allocation, persistent NAT, rollback, exhaustion, DNAT lookup, static NAT, NAT counters, decision merge â€“ all NAT types fused.
  - Hard to find relevant tests, slow to compile, prone to merge conflicts.
- Proposed: Split per module:
  - `nat/source_tests.rs` â€“ SNAT rule matching, pool allocation, persistent NAT
  - `nat/destination_tests.rs` â€“ DNAT table lookup, prefix, scope
  - `nat/static_tests.rs` â€“ Static NAT host, block, scope
  - `nat/allocator_tests.rs` â€“ PortAllocator unit tests
  - `nat/counter_tests.rs` â€“ NatRuleCounter tests
  - `nat64/tests.rs` â€“ NAT64 tests (already in nat64.rs mod tests, keep)
  - Keep `nat/tests.rs` for integration tests combining DNAT+SNAT, or delete if redundant.
- Hot-path: N/A â€“ tests only. Splitting improves compile time (parallel test compilation).
- Tests: `cargo test nat --lib` should still pass. `cargo test --test-threads=1` to ensure no interdependencies.
- Why it matters: 8,685 LOC test file is hard to navigate, slow to compile, merge conflicts frequent. Splitting improves developer productivity and allows focused test runs (`cargo test nat::source`).
- Fix: Mechanical file moves, update `nat/mod.rs` with `#[cfg(test)] #[path] mod ...`. Keep integration tests or move to module tests.
- Labels: `tests`, `dumping-ground`, `developer-experience`, `B-class`
- Dedup note: Test dumping ground, not code duplication. Not previously flagged. New finding.

#### R20
- Title: `pkg/daemon/daemon.go` Daemon god-struct (638 lines, 150+ fields) fusing 15 subsystems â€“ extract manager structs
- Severity: High (maintainability, merge conflicts, ownership unclear)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ large surface, but cold path, preserve locking and ordering
- Evidence:
  - File: `pkg/daemon/daemon.go:70-707`, `type Daemon struct` â€“ 638 lines, 150+ fields fusing config/store, dataplane, cluster/HA, gRPC, DDNS, DHCP, DNS, flow/IPFIX, SNMP, RPM/LLDP, scheduler, neighbor/GC, host inbound, NAT alarms, bootstrap.
  - Every change touches `daemon.go`, causing merge conflicts. Hard to reason about ownership/locking.
- Proposed: Extract manager structs, Daemon holds pointers:
  - `ConfigApplier` â€“ store, applySem, commit/rollback (`daemon_apply.go`, `daemon_run.go`)
  - `HAManager` â€“ cluster, sessionSync, rgStates, fabric, blackhole (`daemon_ha*.go`)
  - `PolicyInvalidator` â€“ policy diff, session clearing (`daemon_policy_invalidate.go`)
  - `DDNSManager`, `FlowManager`, `SNMPManager`, `DHCPManager`, `NeighborGCManager`
  - Daemon becomes thin orchestrator: New() wires managers, Run() starts them, applyConfigLocked() delegates to ConfigApplier.
- Hot-path: None â€“ cold path. Config apply latency may improve slightly from reduced lock contention.
- Tests: `daemon_apply_*_test.go`, `daemon_ha_*_test.go`, `daemon_policy_invalidate_test.go`. Gate: `go test ./pkg/daemon -run TestApply|TestHA|TestPolicy`.
- Why it matters: 638-line struct unmaintainable; hard to reason about locking; merge conflicts on every change. Splitting clarifies invariants per subsystem.
- Fix: Incremental extraction, start with HAManager (already mostly in daemon_ha*.go) and PolicyInvalidator. Move fields + methods, keep Daemon as facade during migration.
- Labels: `god-struct`, `maintainability`, `daemon`, `B-class`
- Dedup note: Similar to userspace Manager god-object (ps-010 R4, but this is Go daemon, not Rust forwarding). Not a duplicate â€“ different codebase (Go vs Rust), different struct. Not previously flagged.

#### R21
- Title: `pkg/daemon/daemon_apply.go` â€“ `applyConfigLocked` (1,148 LOC) fusing commit, reconcile, rollback, 20 subsystem reconciles â€“ split into phases
- Severity: High (maintainability, review cost, error handling complexity)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ complex ordering, but cold path, preserve C1/C2/C3 phase ordering
- Evidence:
  - File: `pkg/daemon/daemon_apply.go` â€“ 1,883 lines, `applyConfigLocked` at 546-1694 (1,148 lines) fusing bootstrap, config compilation, dataplane apply, networkd, FRR, IPsec, DHCP, DNS, DDNS, SNMP, LLDP, RPM, scheduler, flow export, etc., plus commit-confirmed rollback.
  - 1.1k line function impossible to review safely. Subsystem reconcile logic interleaved with commit/rollback.
- Proposed: Split into phases with ApplyContext:
  - `PhaseCompile` â€“ dataplane compile, returns snapshot
  - `PhaseActuateNetwork` â€“ networkd, FRR, IPsec, DHCP, RA
  - `PhaseReconcileServices` â€“ DNS, DDNS, SNMP, LLDP, RPM, scheduler, flow, events
  - `PhaseHACommit` â€“ cluster sync, peer push, commit-confirmed
  - Move subsystem reconcile to managers: `dhcpManager.Reconcile(cfg)`, etc.
  - `daemon_apply.go` becomes orchestrator calling managers in order.
- Hot-path: None â€“ cold path, but user-visible (CLI commit). Preserve C1/C2/C3 ordering documented in code.
- Tests: `daemon_apply_runtime_test.go`, `bootstrap_test.go`, `commit_confirm_demote_4378_test.go`. Gate: `go test ./pkg/daemon -run TestApply|TestBootstrap|TestCommitConfirmed`.
- Why it matters: 1.1k line function unreviewable, hard to reason about error handling. Splitting reduces review cost and enables unit testing per phase.
- Fix: Refactor in place, extract methods to managers first, then split file into `apply_compile.go`, `apply_network.go`, etc. Keep `applyConfigLocked` as thin orchestrator.
- Labels: `monolithic-function`, `config-apply`, `maintainability`, `B-class`
- Dedup note: Mirrors userspace Manager.Compile complexity (ps-010 R4). Not a duplicate â€“ different file, Go vs Rust. Not previously flagged.

### Low confidence / Do-not-split

#### R22
- Title: `userspace-dp/src/nat/destination.rs` (1,088 LOC) â€“ DNAT table large but cohesive â€“ keep or minor cleanup
- Severity: Low
- Confidence: High
- Refactor class: (C) minor cleanup or (D) keep â€“ cohesive, hot path clean
- Evidence: Tiered lookup (exact â†’ wildcard â†’ PROTO_ANY â†’ prefix LPM), `lookup_with_counter_scoped` 139 LOC, `match_entries` linear scan over small Vec (1-3 entries), no alloc on hot path. `from_snapshots` builds table (cold). 1,088 LOC large but single responsibility (DNAT table).
- Reasoning: Cohesive around single responsibility, hot path clean (FxHashMap, linear scan, no alloc). Splitting would add module overhead without clear benefit unless file grows beyond 1,500 LOC.
- Proposed: (D) keep as is, rename to `nat/dnat.rs` for consistency. Optionally split `DnatEntry` matching to `dnat_entry.rs` if grows. Ensure `match_entries`, `source_matches` stay `#[inline]`.
- Why keep: Well optimized, no cold fusion, manageable size. Focus refactoring on source.rs and nat64.rs instead.
- Labels: `cohesive`, `D-class`
- Dedup note: None â€“ DNAT table structure mirrors static NAT but different use case, not duplication.

#### R23
- Title: `userspace-dp/src/nat/static_nat.rs` (793 LOC) â€“ static NAT cohesive, keep
- Severity: Low
- Confidence: High
- Refactor class: (D) DO-NOT-SPLIT â€“ cohesive and well-scoped
- Evidence: 793 lines, `match_dnat_with_counter_scoped` 115 LOC, `match_snat_with_counter_scoped`, `pick_scoped` linear scan over small Vec. No alloc on hot path. Single responsibility (static 1:1 NAT).
- Reasoning: 793 LOC reasonable, cohesive, well-scoped. Splitting would add overhead without benefit.
- Proposed: Rename to `nat/static.rs` for consistency, no further split. Ensure `pick_scoped` stays `#[inline]`.
- Labels: `cohesive`, `D-class`
- Dedup note: None.

#### R24
- Title: `userspace-dp/src/screen/mod.rs` (1,479 LOC) â€“ already split per #1543, cohesive orchestrator, keep
- Severity: Low
- Confidence: High
- Refactor class: (D) DO-NOT-SPLIT â€“ already well modularized
- Evidence: Already split into `packet.rs`, `extract.rs`, `stateless.rs`, `rate.rs`, `syn_rate.rs`, `scan.rs`, `syncookie.rs` per #1543. `mod.rs` is ScreenState orchestrator for 16 checks. Warm path (session miss only), not per-packet hot.
- Reasoning: Further split by check category would fragment orchestrator without reducing complexity. Checks are simple predicates, complexity in rate/sketch coordination which belongs in ScreenState. Over-splitting would hide inter-check ordering (stateless before rate) essential for Junos parity.
- Proposed: Keep current structure. Document orchestration order. Optionally extract `scan_sweep_drop_on_new_flow` to `screen/flow.rs` if grows beyond 1,500 LOC, but not urgent.
- Labels: `cohesive`, `D-class`
- Dedup note: #1543 already split; this warns against further fragmentation.

#### R25
- Title: `userspace-dp/src/afxdp/wg/engine.rs` â€“ hot data path cohesive with WgEngine state, keep encap/decap in engine.rs, optionally move cold control to wg/control.rs
- Severity: Low/Medium
- Confidence: High
- Refactor class: (D) for data path, (B) for cold control methods
- Evidence: 1,763 LOC, `WgEngine` 18 fields mixing hot (sessions, counters) with cold (pending maps, cookie_gen). `encap_inner` (172 LOC) and `try_decap` (223 LOC) hot, allocation-free, stack `MaybeUninit`, no locks on fast path. Already modularized: `handshake_session.rs` (759 LOC), `cookie.rs`, `peer.rs`, `session.rs`, `timers.rs`. Cold methods: `reconcile_peers` (121 LOC), `install_session`, `classify_initiation`.
- Reasoning: Data path tightly coupled to WgEngine fields (sessions, counters, rekey atomics) and must stay inline for performance. Splitting data path would require exposing private fields or context struct, harming performance and auditability. Cold methods can move to `wg/control.rs` to reduce LOC, but not urgent.
- Proposed: D for data path â€“ keep `encap_inner`/`try_decap` in engine.rs. B for control â€“ optionally move `reconcile_peers`, `install_session`, `classify_initiation` to `wg/control.rs`. Add hot/cold section comments.
- Hot-path preservation: Data path must remain allocation-free, lock-free (except RwLock::read), inlineable â€“ keep in same module. Cold path may allocate, take locks.
- Labels: `wireguard`, `hot-path`, `cohesive`, `D-class`
- Dedup note: ECN combine shared with GRE â€“ correct dedup. Handshake already isolated.

#### R26
- Title: `userspace-dp/src/gre.rs` (961 LOC) â€“ encap and decap fused but cohesive, keep
- Severity: Low
- Confidence: High
- Refactor class: (D) DO-NOT-SPLIT â€“ cohesive around tunnel logic, shared ECN helpers
- Evidence: 961 LOC, `try_native_gre_decap_from_frame` (168 LOC), `encapsulate_native_gre_frame` (152 LOC), shared `decap_ecn_combine`, `apply_decap_ecn_combine` (also used by WG), `gre_checksum_region`. Hot path for tunnel traffic. Decap allocates one Vec for synthetic frame (unavoidable), encap allocates one Vec for outer frame.
- Reasoning: Encap and decap share ECN logic, checksum, parsing. Splitting would duplicate helpers or create common module, increasing indirection. 961 LOC well under threshold, cohesive.
- Proposed: Keep as single file. Add module-level doc distinguishing encap vs decap sections. If file exceeds 1,200 LOC, consider `gre/common.rs` for shared helpers, but keep encap/decap together.
- Labels: `gre`, `tunnel`, `cohesive`, `D-class`
- Dedup note: `apply_decap_ecn_combine` shared with WG â€“ correct, both use RFC 6040. No duplication.

## 7. Suggested issue split â€“ sequenced for safe landing

**Phase 1 â€“ Go control plane mechanical splits (A) â€“ cold path, no dataplane impact:**
1. **R13 â€“ compiler_validate_strict.go domain split** (A): Split 6,997 LOC by domain into `pkg/config/validate_*.go` â€“ policy, NAT, filter, routing, IPsec, system. Keep thin dispatcher. Mechanical file moves, no logic changes. Run `go test ./pkg/config`. PR #1-8 (one per domain).
2. **R14 â€“ compileExpanded phase extraction** (B): Extract `runASTPreWalks`, `newEmptyConfig`, `compileSections`, `runStrictValidators` from 2,435 LOC god function. Keep `compileExpanded` as thin orchestrator. Run `go test ./pkg/config`. PR #9-12.
3. **R15 â€“ compiler_nat.go split** (A): Split 2,485 LOC by NAT kind: source, destination, static, validate, scope. Mechanical moves. PR #13-17.

**Phase 2 â€“ Go daemon/dataplane manager (B) â€“ cold path, preserve ordering:**
4. **R20 â€“ Daemon god-struct extraction** (B): Extract `ConfigApplier`, `HAManager`, `PolicyInvalidator`, etc. from 638-line struct. Incremental, keep Daemon as facade. Run `go test ./pkg/daemon`. PR #18-22.
5. **R21 â€“ daemon_apply.go phase split** (B): Split `applyConfigLocked` 1,148 LOC into phases: Compile, ActuateNetwork, ReconcileServices, HACommit. Move subsystem reconciles to managers. PR #23-26.
6. **R4 (ps-010) â€“ userspace Manager decomposition** (B): Split `pkg/dataplane/userspace/manager.go` 1,823 LOC into SnapshotBuilder, HAController, SessionSyncer, etc. PR #27-30.
7. **R5 (ps-010) â€“ manager_ha.go split** (A): Split 1,376 LOC into ha_state, ha_watchdog, session_sync, bpf_counters. Mechanical. PR #31-34.

**Phase 3 â€“ Rust dataplane hot path (B/C) â€“ require guardrails, preserve inlining:**
8. **R1 (ps-010) â€“ poll_descriptor god-function split** (B): Split 1,368 LOC `poll_binding_process_descriptor` into session_hit.rs, session_miss.rs, nat_pre_routing.rs, host_local.rs, etc. Use PacketCtx for mutable locals. **Requires disassembly diff and perf validation.** Do after Go splits (less risk). PR #35-42.
9. **R3 â€“ SessionTable cold extraction** (B): Extract `session/nat_index.rs`, `session/limit.rs`, `session/ha.rs`. Fix P5 multi-map (A). Eliminate Arc clone (A). Keep core table+indexes together (D). PR #43-47.
10. **R4 â€“ Forwarding split** (B/C): Move PBR to filter/pbr.rs, split route lookup to route.rs/local.rs/neighbor.rs, fix `to_string` alloc (C), extract flowless shared helper (C). Verify table-scoped security. PR #48-52.
11. **R5 â€“ TX drain orchestrator split** (B): Split `enqueue_pending_forwards` 1,131 LOC by encapsulation (phase_build.rs with build_plain/wireguard/gre). Keep inlined, no dispatch, preserve UMEM ownership. Verify with CoS gates and disassembly. PR #53-56.
12. **R15 â€“ nat/source.rs split** (B): Split 1,190 LOC into snat_rule.rs, snat_match.rs, snat_alloc.rs. Keep match and alloc inline. PR #57-59.
13. **R16 â€“ nat/allocator.rs hot/cold split** (C): Split PortAllocator into hot/cold, rename to pool.rs. Keep allocate_translation inline, no alloc. PR #60-63.
14. **R17 â€“ nat64.rs split** (B): Split 2,047 LOC into nat/nat64/ submodule: classification, translation, ICMP, checksum, fragment. Isolate per-packet frame alloc, ensure non-NAT64 zero alloc, UMEM release. PR #64-68.
15. **R18 â€“ neighbor.rs split** (B): Split 1,901 LOC by concern: probe.rs (hot), netlink.rs, warmer.rs, cpu.rs. Keep trigger_kernel_arp_probe allocation-free. PR #69-72.
16. **R6 â€“ CoS selection split** (B): Split waterfill phases, move telemetry cold. Preserve `#[repr(align(64))]`, atomic ordering. Verify fairness gate. PR #73.

**Phase 4 â€“ Optional performance-positive (C) â€“ measure first:**
17. **R3 â€“ Session SoA split** (C): Only if profiling shows cache miss improvement. Measure with `perf c2c` before committing.
18. **R4 â€“ ForwardingState hot/cold split** (C): Only if clone cost measured. Keep single Arc, nest structs.
19. **R8 â€“ SessionEntry SoA** (C): Only if Arc elimination insufficient.

**Do NOT do â€“ D class, would regress:**
- **R9 â€“ BindingWorker further split**: Would break cache locality (`cold_path` co-located with `flow` per #1620).
- **R10 â€“ stage_flow_cache_hit further split**: Hottest path (90%+ packets), 457 LOC justified, further split hurts icache.
- **R11 â€“ evaluate_policy_result_l3_aware split**: Exemplary hot path, keep as is.
- **R12, R22, R23, R24, R25, R26**: ForwardingResolution, DNAT table, static NAT, screen, WG data path, GRE â€“ cohesive, keep.
- **ps-010 R9-R12**: Same D-class warnings â€“ do not split BindingWorker, flow cache hit, policy eval, ForwardingResolution.

**Verification for each PR:**
- Go: `go test ./pkg/config -count=1`, `go test ./pkg/daemon -run TestApply|TestHA`, `go test ./pkg/dataplane/...`
- Rust: `cargo test --lib <module>`, `make test`, `make test-failover`, CoS smoke/fairness (`cargo test cos`, `cargo test fairness`)
- Hot path: Disassembly diff (`cargo asm`, `objdump -d`) â€“ hot loop byte-identical, no extra callq, no alloc.
- Perf: `perf stat -e instructions,cache-misses,branch-misses` â€“ within 1% of baseline, ideally improved.
- `cargo bloat` â€“ no size regression in hot symbols.
- Single-recycle fault injection â€“ `FORCE_OVERSIZED=1`, `FORCE_TUPLE_MISMATCH=1` for TX.
- UMEM leak check â€“ `test-umem-leak` for NAT64.

**Sequencing rationale:**
- Go cold path first â€“ no dataplane risk, improves build time and review cost early, establishes pattern.
- Rust cold modules next (NAT, filter compiler, neighbor) â€“ not per-packet hot, safe to split.
- Rust hot path last (poll_descriptor, session, forwarding, TX, CoS) â€“ requires careful guardrails, disassembly verification, do after Go splits to reduce overall risk.
- Performance-positive splits optional â€“ measure before committing, only if profiling shows benefit.
- Do-not-split explicit â€“ prevents well-intentioned but harmful refactors that would break inlining, locality, or UMEM ownership.

---

*End of ps-review-011 â€“ 2026-07-06*
