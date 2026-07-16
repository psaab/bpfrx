# 039 A2 — NAT (Rust nat/*.rs + nat64/nptv6 + Go NAT compile) — Monolith Audit

## File-size / shape inventory (base f7014695)

| File | LOC | Prod/Test | Responsibilities | Largest fn |
|------|-----|-----------|------------------|------------|
| `userspace-dp/src/nat/allocator.rs` | 1416 | prod | 5 structs (PortAllocator, PortAllocatorShared, AddressOccupancy, PortAllocatorLiveState, LiveAllocation) + PersistentLease + DeterministicV4 + GC + recycle + deterministic reverse | `allocate_translation` 100 LOC, `allocate_translation_locked` 114 LOC |
| `userspace-dp/src/nat/source.rs` | 1389 | prod | SourceNatRule (20+ fields) + 6 type defs + pool expansion + rule parsing + scope/l4/prefix matching + match driver + 6 release/reserve wrappers + 3 NAT64 wrappers + deterministic path | `match_source_nat_result_for_tuple` 336 LOC (line 996-1330) |
| `userspace-dp/src/nat/destination.rs` | 1088 | prod | DnatTable exact+wildcard+PROTO_ANY+prefix-LPM, DnatEntry, DnatPrefixSlot, scope/source/l4 gates, off-exemption, local-address registration | `lookup_with_counter_scoped` ~110 LOC |
| `userspace-dp/src/nat/static_nat.rs` | 793 | prod | StaticNatTable exact+block, StaticNatBlock, SourceConstraint, scope gates, port-mapped coexistence | `from_snapshots` ~110 LOC |
| `userspace-dp/src/nat/mod.rs` | 297 | prod | NatDecision, NatRuleCounter, NatCounterStore, NatScopeCtx, re-exports | — |
| `userspace-dp/src/nat/status.rs` | 40 | prod | Thin snapshot aggregation | — |
| `userspace-dp/src/nat/tests_pool.rs` | 3828 | test | 79 tests pool/persistent/allocator/HA-reserve | — |
| `userspace-dp/src/nat/tests_destination.rs` | 1654 | test | 41 tests DNAT | — |
| `userspace-dp/src/nat/tests_static.rs` | 1109 | test | 31 tests static | — |
| `userspace-dp/src/nat/tests_l4_match.rs` | 815 | test | 17 tests L4/app | — |
| `userspace-dp/src/nat/tests_scope.rs` | 607 | test | 17 tests scope/interface/RI | — |
| `userspace-dp/src/nat/tests_source.rs` | 570 | test | 16 tests source parsing | — |
| `userspace-dp/src/nat/tests_counter.rs` | 357 | test | 6 tests counter | — |
| `userspace-dp/src/nat/tests_dnat_proto.rs` | 348 | test | 10 tests proto | — |
| **nat prod total** | **5023** | | | |
| **nat test total** | **9288** | | | |
| `userspace-dp/src/nat64.rs` | 2527 | prod | Nat64State, Nat64Prefix, forward/reverse translate, EH walk, frag, ICMP-embed | `translate_v6_to_v4` ~200 LOC |
| `userspace-dp/src/nptv6.rs` | 431 | prod | Nptv6State, prefix translate, checksum adjust | — |
| `userspace-dp/src/nat64_tests.rs` | 3984 | test | | |
| `userspace-dp/src/nptv6_tests.rs` | 790 | test | | |
| `pkg/config/compiler_nat.go` | 2529 | prod | ~37 funcs: 5 NAT types compile + 4 validators + 8 helpers + deterministic | `compileNATSource` ~500 LOC, `validateNPTv6Strict` ~200 LOC |
| `userspace-xdp/src/lib.rs` | 1541 | prod | No NAT classification logic (DNAT maps only) | — |

---

## Finding A2-1: nat/allocator.rs — PortAllocatorShared god-struct: hot bitmap + cold persistent-leases/GC/stats fused

**Severity:** Medium
**Confidence:** High
**Refactor class:** (C) PERFORMANCE-POSITIVE (with foot-gun)

**Evidence:**

`PortAllocator` is thin, but its shared state is monolithic:

```rust
// allocator.rs:458
struct PortAllocatorShared {
    counters: Vec<AtomicU32>,          // cold: addr-only try_next_port
    addr_counter_v4: AtomicU32,         // cold: round-robin
    addr_counter_v6: AtomicU32,
    occupancy: Vec<AddressOccupancy>,  // HOT: bitmap + cursor, every new flow
    live: Mutex<PortAllocatorLiveState>, // cold: flow map + persistent leases
    allocations_total: AtomicU64,      // cold: stats
    reuses_total: AtomicU64,
    exhaustion_total: AtomicU64,
    max_tracked_flows: usize,          // config
}
```

```rust
// allocator.rs:284
struct AddressOccupancy {
    words: Vec<AtomicU64>,    // HOT: CAS claim
    cursor: AtomicU32,        // HOT: fetch_add cursor
    recycle: Mutex<VecDeque<u16>>, // semi-hot: FIFO
    port_low: u16,
    range: u32,
}
```

```rust
// allocator.rs:258
pub(super) struct PortAllocatorLiveState {
    live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
    persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
    lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
    lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>>,
    gc_counter: u32,
}
```

No `#[repr]`, no cache-line separation. Hot fields (`occupancy.words`, `occupancy.cursor`) share cache lines with cold atomics (`allocations_total`, `addr_counter_*`) via `PortAllocatorShared`. The comment on line 1-22 itself notes Phase 2 hash-sharding is deferred because Phase 1 single-mutex was the bottleneck — but the hot/cold fusion remains.

Count: 5 cold responsibilities (stats, GC, persistent-lease lifecycle, two expiration indexes, addr round-robin) + 1 hot (bitmap claim) + 1 semi-hot (recycle). Largest method `allocate_translation` 100 LOC (`reserve_flow` is hot-path, every new flow per #4388/#4399).

**Proposed decomposition:**

```
allocator/
  mod.rs              // PortAllocator pub surface, PortAllocatorSnapshot
  hot_bitmap.rs       // AddressOccupancy — words, cursor, claim_offset/free_offset/claim/reserve, #[repr(align(64))]
  live_state.rs       // PortAllocatorLiveState — live_by_flow, persistent_by_source, expiration indexes, gc_counter
  persistent.rs       // PersistentLease, PersistentSourceKey, reuse_existing_lease_locked, gc_expired_*
  deterministic.rs    // DeterministicV4, deterministic_indices_v4, reverse_deterministic_v4, allocate_deterministic_v4
  stats.rs            // allocations_total/reuses_total/exhaustion_total snapshot helpers
```

Keep `PortAllocatorShared` but split physically:

- `hot: Box<[HotAddress]>` where `HotAddress` is `#[repr(align(64))]` containing only `words`, `cursor` (and maybe `port_low/range` if needed for offset_of). This reduces cache footprint for `allocate_translation` non-persistent fast path (line 718-769) which currently touches `self.shared.occupancy[abs].claim()` then `self.shared.live.lock()` — the lock is cold but `occupancy` itself is hot.
- Cold stays behind Arc: `live`, stats, round-robin counters.

Critical: do NOT add a pointer chase between hot bitmap lookup and claim. Current `self.shared.occupancy[abs].claim()` is one deref (`Arc` -> `Vec` -> `AddressOccupancy`). Splitting must keep `occupancy` in same allocation as PortAllocator or in a sibling `Arc` with same indirection depth. Adding a second `Arc<HotState>` would add one more indirection on hot path — measurable.

**Hot-path preservation:**

- `reserve_flow` (#4388) and `allocate_translation` non-persistent hot path run every new flow, must stay zero-alloc, no Vec alloc, no lock on claim. The split must preserve:
  - `AddressOccupancy::claim` remains `&self` with only `AtomicU64` CAS + `AtomicU32` cursor + one `Mutex<VecDeque>` only when cursor exhausted (recycle phase). No new allocation in claim.
  - `reserve_flow` CAS path (`occupancy[addr_index].reserve(port)`) stays lock-free.
  - `live_by_flow` insert stays under existing tiny mutex, not expanded.
  - Per engineering-style.md: pre-size Vecs, never allocate per-packet. The `retained: Vec<u16>` in `claim()` already allocates lazily only on collision — acceptable cold.

Guardrail: run `benches/snat_allocator.rs` (results in `docs/research/2852-portalloc/`). Pre-#2852 single mutex negative-scales 2.87M→0.62M allocs/sec M=1→8. Phase 1 is 1.4-1.6x at M=6/8. Any hot/cold split must not regress below Phase 1.

**Tests+gate:**

- `cargo test -p userspace-dp nat::tests_pool` (79 tests) — covers port-less, ICMP id==0, no-translation, subnet expansion, persistent 3-way, expiry index invariant, pressure GC, shared-pool exhaustion, reserve_flow collision.
- `cargo test -p userspace-dp --lib` for allocator white-box (`debug_is_port_occupied`, `debug_recycled_ports`, etc.)
- `cargo bench -p userspace-dp snat_allocator` — verify no regression vs 2852 baseline.

**Why it matters:** PortAllocator is on the hot path for every new flow (pool-mode SNAT + NAT64 via `allocate_nat64_pool_port`). The current `PortAllocatorShared` mixes hot atomics (bitmap words, cursor) with cold atomics (stats counters, round-robin address counters) on the same cache line. Under 6-8 worker contention this causes false-sharing invalidations on every atomic increment (stats bump at line 765-768) even when workers are claiming distinct pool addresses. Splitting hot bitmap into its own cache-line-aligned struct reduces coherence traffic — but only if done without adding indirection.

**Fix direction:** Introduce `#[repr(align(64))]` `HotOccupancy` for the bitmap+cursor. Move stats/counters to separate `ColdStats`. Keep `occupancy: Vec<HotOccupancy>` flat, not `Vec<Arc<...>>`. Document cache-line reasoning in comment (like existing #2852 comment). No behavior change.

**Labels:** perf, nat, allocator, hot-path, refactor

**Dedup note:** Overlaps #4409 "nat/allocator.rs PortAllocator god-struct (926 LOC)" — this is the same file, now 1416 LOC (+490 LOC from deterministic + persistent refinements). #4409 was filed as open refactor. This finding is a refined, measurement-gated decomposition proposal with explicit hot/cold classification and `#[repr(align)]` guardrail. Not a duplicate — enriches #4409 with performance-positive split analysis.

---

## Finding A2-2: nat/source.rs — match_source_nat_result_for_tuple 336 LOC god-function + 6 responsibilities in one file

**Severity:** Medium
**Confidence:** High
**Refactor class:** (B) STRUCTURAL (moderate risk)

**Evidence:**

```rust
// source.rs:996 (336 LOC, >3x the 100-LOC god-function threshold)
pub(crate) fn match_source_nat_result_for_tuple(
    rules: &[SourceNatRule],
    scope: &NatScopeCtx,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
    now_ns: u64,
    non_first_fragment: bool,
    icmp_identifier_present: bool,
    matched_counter: &mut Option<Arc<NatRuleCounter>>,
) -> SourceNatLookup {
    // responsibilities in one function:
    // 1. zone/scope match (via rule.matches)
    // 2. off/interface-mode early-return
    // 3. pool_mode + pool_failure gate
    // 4. non-first-fragment gate (#1852)
    // 5. ICMP query vs port-less vs tuple-unknown vs no-translation classification (#3111/#4074/#4088/#3906)
    // 6. v4 vs v6 pool selection + deterministic vs round-robin vs persistent dispatch
```

File `source.rs` totals 1389 LOC with responsibilities:
- Type defs: `SourceNatFailure`, `SourceNatFailureReason` (8 variants), `SourceNatFlowKey`, `PersistentNatPermit`, `SourceNatAppTerm`, `SourceNatRule` (20+ fields), `SourceNatPoolAllocatorKey`
- Pool expansion: `expand_pool_address` (50 LOC)
- Rule parsing: `parse_source_nat_rules_with_previous` (189 LOC) + `parse_match_prefix`
- Match helpers: `scope_matches`, `l4_matches`, `matches`, `nets_match_v4/v6`, `port_in_ranges`
- Allocation driver: `match_source_nat_result_for_tuple` 336 LOC (largest), `match_source_nat_result` 30 LOC, `match_source_nat` 15 LOC
- Release/rollback/reserve: 6 fns `release_source_nat_allocation`, `rollback_source_nat_allocation`, `release_source_nat_allocation_with_mode`, `reserve_synced_source_nat_allocation`, plus 3 NAT64 wrappers
- Deterministic glue already in allocator.rs

13-param function `match_source_nat_result_for_tuple` has 4 nested `match src_ip` arms each duplicating the address-only vs PAT pattern (v4 deterministic, v4 PAT, v6 PAT, wrong-family). The deterministic block (lines 1152-1206) is 55 LOC inline; the port-less gate (lines 1131-1142) is 12 LOC with 3 boolean flags.

**Proposed decomposition:**

```
nat/source/
  mod.rs              // re-exports, SourceNatRule, SourceNatFlowKey, SourceNatFailure
  types.rs            // PersistentNatPermit, SourceNatAppTerm, SourceNatPoolAllocatorKey, SourceNatFlowKey::persistent_source_key
  parse.rs            // parse_source_nat_rules_with_previous, expand_pool_address, parse_match_prefix, source_nat_runtime_compatible (cold, config-time)
  match_rules.rs      // scope_matches, l4_matches, matches, nets_match_*, port_in_ranges (pure predicates)
  match_driver.rs     // match_source_nat_result_for_tuple split:
                      //   classify_l4_mode(protocol, icmp_id_present, no_translation) -> L4Mode enum
                      //   pick_pool_translation(rule, flow, src_ip, family, mode, now_ns) -> Result<TranslatedTuple>
                      //   match_source_nat_result_for_tuple — thin orchestrator (<80 LOC) calling above
  release.rs          // release_source_nat_allocation*, rollback_*, reserve_synced_*
  nat64_glue.rs       // allocate_nat64_pool_port, release_nat64_pool_port, reserve_nat64_pool_port
```

Key split: `match_source_nat_result_for_tuple` →

- `fn classify_l4_mode(protocol: u8, icmp_id_present: bool, no_translation: bool) -> L4Mode { PortLess | AddressOnly { tuple_unknown: bool } | NoTranslation | Pat { icmp_query: bool } }` — pure, no alloc, testable.
- `fn allocate_pool_v4(rule, flow, src_v4, mode, now_ns) -> Result<NatDecision>` — extracts lines 1143-1262 (v4 deterministic + PAT)
- `fn allocate_pool_v6(rule, flow, src_ip, mode, now_ns) -> Result<NatDecision>` — v6 path

This keeps the hot path (called on every new flow miss) tight while making the ICMP/port-less/no-translation interaction testable in isolation.

**Hot-path preservation:**

- `match_source_nat_result_for_tuple` is cold-path (session-miss, first packet of flow) — not per-packet hot, but still high-frequency under SYN flood (100k flows/sec). Must stay zero-alloc: no `Vec` clone, no `String` alloc. Current code is already zero-alloc (iterates `rules` slice, borrows). Split helpers must remain `#[inline]` and take `&SourceNatRule`, not owned.
- `classify_l4_mode` is branchless arithmetic on `protocol` + 2 bools — inlineable.
- No new `Arc` clone on hot path beyond existing `hit_counter.clone()` (already there).

**Tests+gate:**

- `cargo test -p userspace-dp nat::tests_source` (16 tests) + `nat::tests_pool` (79) + `nat::tests_l4_match` (17) + `nat::tests_scope` (17)
- New unit tests: `classify_l4_mode` truth table — protocol 0, 6, 17, 1/58 (ICMP), GRE/ESP (47/50), with/without `icmp_identifier_present`, with/without `no_translation` — 12 cases.

**Why it matters:** The 336-LOC function spans 6 distinct concerns with 3 boolean flags (`port_less`, `tuple_unknown`, `address_only`) plus an `icmp_query` bool, then branches into 4 pool-family arms. The #3906 `no_translation` addition and #4074/#4088 ICMP gate were both layered onto the same function, increasing the risk of a future "add one more flag" regression (the #3111 GRE/ESP corruption was exactly this class — a new protocol added without updating the narrow `protocol == 0` gate). Extracting `classify_l4_mode` as a pure function with exhaustive enum makes the next protocol addition a compile-time match-arm, not a boolean-flag hunt.

**Fix direction:** First PR: extract `classify_l4_mode` + `port_in_ranges`/`nets_match_*` into `match_rules.rs` (pure code-motion, no behavior change). Second PR: extract `allocate_pool_v4`/`v6` from the large match driver. Keep each PR <200 LOC net new logic.

**Labels:** refactor, nat, complexity, god-function

**Dedup note:** Overlaps #4409 "nat/source.rs (1,190 LOC)" — now 1389 LOC (+199). #4409 flagged the file size; this finding pins the specific 336-LOC function and proposes a concrete enum-based decomposition. Complements #4409.

---

## Finding A2-3: pkg/config/compiler_nat.go 2529 LOC — 5 NAT types + 4 validators + helpers fused

**Severity:** Low (code health, not perf)
**Confidence:** High
**Refactor class:** (A) MECHANICAL — pure file split, no logic change

**Evidence:**

37 functions in one file:

- NAT type compilers: `compileNATSource` (500 LOC), `compileNATDestination` (~200 LOC), `compileNATStatic` (~200 LOC), `compileNAT64` (20 LOC), proxy-ARP in `compileNAT` (50 LOC), `compileNAT` dispatcher (120 LOC)
- Validators (strict-vs-lenient): `validateNATHostMaskStrict` (120 LOC), `validateNPTv6Strict` (200 LOC), `validateNAT64PrefixStrict` (60 LOC), `validatePoolUtilizationAlarm` (25 LOC), `validateStaticNATThenTargetStrict` (35 LOC)
- Helpers: `natAddrFamily`, `natCIDRIPPart`, `isHostMaskAddress`, `natStaticPrefixInfo`, `isStaticBlockPair`, `isNAT64PoolHostAddress`, `nptv6PrefixHasHostBits`, `parseZoneList`, `parseNATMatchScopes`, `collectNATScopes`, `applyNATFromScope`, `applyNATToScope`, `applyStaticNATFromScope`, `appendPoolAddresses`, `expandAddressRange`, `parseSourcePoolPortRange`, `applyDeterministicKeys/Children/Host`, `parseDNATPoolAddress`, `parseDNATPortList`, `appendDNATPortRange`, `staticNATMappedPortFromKeys`, `staticNATRoutingInstanceFromKeys`, `resolveStaticNATThenPrefixName(s)`, `defaultPoolAlarmClearThreshold`

The file mixes:

1. AST parsing (hierarchical vs flat-set dual shape — `parseNATMatchScopes`, `parseZoneList`, bracket-list handling)
2. Semantic validation (host-mask, NPTv6 overlap, NAT64 /96, pool alarm, static then-target)
3. Typed-config building (`compileNATSource` etc.)

The comment at line 831 documents the dup-block accumulation fix (#3915) — but the same file also carries unrelated NPTv6 host-bits validation (#2380) and proxy-ARP range expansion. Changing one NAT type requires reading the entire 2529 LOC file.

**Proposed decomposition:**

```
pkg/config/
  compiler_nat.go              // ~80 LOC: compileNAT dispatcher + forEachChild loops
  compiler_nat_source.go       // compileNATSource, appendPoolAddresses, expandAddressRange, parseSourcePoolPortRange, applyDeterministic*, parseZoneList, parseNATMatchScopes, collectNATScopes, applyNATFromScope/ToScope
  compiler_nat_destination.go  // compileNATDestination, parseDNATPoolAddress, parseDNATPortList, appendDNATPortRange
  compiler_nat_static.go       // compileNATStatic, staticNATMappedPortFromKeys, staticNATRoutingInstanceFromKeys, resolveStaticNATThen*, validateStaticNATThenTargetStrict, applyStaticNATFromScope
  compiler_nat_nat64.go        // compileNAT64, isNAT64PoolHostAddress, validateNAT64PrefixStrict
  compiler_nat_validate.go     // validateNATHostMaskStrict, validateNPTv6Strict, validateNAT64PrefixStrict, validatePoolUtilizationAlarm, defaultPoolAlarmClearThreshold, nptv6PrefixHasHostBits
  compiler_nat_helpers.go      // natAddrFamily, natCIDRIPPart, isHostMaskAddress, natStaticPrefixInfo, isStaticBlockPair (shared pure predicates)
```

Each file <600 LOC. No new dependencies, no circular imports (all in `package config`). Pure code-motion: `git mv` + `//go:build` unchanged.

**Hot-path preservation:** N/A — this is compile-time (commit, load, peer-sync), not per-packet. No hot-path concern.

**Tests+gate:**

- `go test ./pkg/config -run TestCompileNAT -count=1`
- `go test ./pkg/config -run TestValidateNAT -count=1`
- `make selftest` — exercises dist roundtrip, validate.py helpers

**Why it matters:** At 2529 LOC this file exceeds the 2000-LOC mod file smell (engineering-style.md: "A .rs file that crosses ~2,000 LOC ... is a smell. Apply same rule to .go"). It is approaching the 3000-LOC "next change should split before adding new logic" threshold. Recent changes (#4290 prefix-name, #4292 routing-instance, #3915 dup-block, #3864 deterministic accumulate) all landed in this single file, increasing merge conflicts. The `validate*Strict` validators are independent of the `compile*` builders — they can be reviewed/tested in isolation.

**Fix direction:** Mechanical split PR: create 6 new files, move functions verbatim, keep `compiler_nat.go` as dispatcher. No behavior change. Second PR (optional): extract `natAddrFamily`/`natCIDRIPPart` into `pkg/config/nat_helpers.go` if reused elsewhere (check via `grep -r natAddrFamily`).

**Labels:** refactor, config, mechanical, file-split

**Dedup note:** Partial overlap with #4056 "NAT compile/validate 5-file-scattered" (open). #4056 describes the problem; this finding proposes concrete file names and function assignments. Also overlaps #4421 "modularity backlog" which lists compiler_nat.go as candidate. Not a duplicate — provides actionable split plan.

---

## Finding A2-4 (D) NEGATIVE — nat/destination.rs is cohesive, not monolithic

**Severity:** N/A
**Confidence:** High
**Refactor class:** (D) NO-OP — do not split

**Evidence:**

`destination.rs` is 1088 LOC with one responsibility: DNAT table. Internal structure:

- `DnatKey` / `DnatValue` / `DnatEntry` / `DnatPrefixSlot` / `DnatProtoPortKey` — all DNAT domain types
- `DnatTable` with 2 maps: `entries: FxHashMap<DnatKey, Vec<DnatEntry>>` (exact) + `prefix_entries: FxHashMap<DnatProtoPortKey, Vec<DnatPrefixSlot>>` (LPM)
- 3-tier lookup: exact `(proto,dst,port)` → wildcard-port `(proto,dst,0)` → `PROTO_ANY` → prefix LPM
- Helpers: `match_entries`, `match_prefix_lpm`, `match_prefix_slots`, `insert_entry`, `insert_prefix_slot`, `destination_ips`, `destination_ips_scoped`, `port_in_ranges`, `host_count_v4/v6`

All helpers serve the single DNAT lookup. No unrelated concerns (no allocator, no pool expansion, no address-book resolution). The 1088 LOC is well under the 2000-LOC monolith threshold. The largest function `lookup_with_counter_scoped` is ~110 LOC, under the 100-LOC god-function threshold (marginally over, but cohesive). The file grew via legitimate feature additions (#3164 prefix LPM, #2394 source-scoped, #3096 interface/RI scope, #3437 ICMP type/code, #3844 off exemption, #3449 dst-port range) — each added a field to `DnatEntry` + a clause in `insert_*` dedup key + a gate in `l4_extra_matches`/`source_matches`/`scope_ok`. This is the expected growth for a lookup table, not a god-struct.

Test coverage: `tests_destination.rs` (41 tests), `tests_dnat_proto.rs` (10), `tests_l4_match.rs` (17, shared with SNAT), `tests_scope.rs` (17) — all exercise DNAT paths.

**Why no split:** Splitting `DnatTable` into `exact.rs` + `prefix.rs` would create two files that always change together (adding a new match field requires updating both dedup keys and both match gates). The current single-file layout localizes the dedup invariant (insert checks same fields as match gates) — splitting would risk drift (the #704 bug class).

**Dedup note:** No open issue proposes splitting destination.rs. #4421 mentions it as part of broader "NAT modules" but does not claim it is monolithic.

---

## Finding A2-5 (D) NEGATIVE — nat/tests already split per #4409, no further action

**Severity:** N/A
**Confidence:** High
**Refactor class:** (D) NO-OP — do not split

**Evidence:**

The original `nat/tests.rs` was 8685 LOC dumping ground (claimed in #4409). It has been split (commit #4409):

```
tests_pool.rs         3828 LOC  79 tests  pool/persistent/allocator/HA-reserve
tests_destination.rs  1654 LOC  41 tests  DNAT
tests_static.rs       1109 LOC  31 tests  static
tests_l4_match.rs      815 LOC  17 tests  L4/app/src-port/ICMP-type
tests_scope.rs         607 LOC  17 tests  interface/RI/zone scope
tests_source.rs        570 LOC  16 tests  source parsing/fail-closed
tests_dnat_proto.rs    348 LOC  10 tests  GRE/ICMP/HOPOPT wildcard
tests_counter.rs       357 LOC   6 tests  counter store/ids/clear
```

Plus `nat64_tests.rs` (3984 LOC) and `nptv6_tests.rs` (790 LOC) separate.

Each file is <4000 LOC, each maps to one NAT concern. `tests_pool.rs` is the largest at 3828 LOC / 79 tests — it covers 5 sub-concerns (port-less, ICMP query-id, no-translation, subnet expansion, persistent NAT) but all are pool-mode SNAT allocation paths that share the same `PortAllocator` setup helpers (`make_pool_rule`, `make_allocator`). Splitting `tests_pool.rs` further would duplicate setup code without improving locality.

**Dedup note:** Directly closes the `nat/tests.rs dumping ground` part of #4409. No further split needed.

---

## Summary of classifications

| Finding | File(s) | LOC prod | Class | Action |
|---------|---------|----------|-------|--------|
| A2-1 | `nat/allocator.rs` (1416) — PortAllocatorShared hot/cold fused | 1416 | (C) PERFORMANCE-POSITIVE (with foot-gun) | Split hot bitmap into `#[repr(align(64))]` struct, keep cold behind Mutex/Arc. Must not add pointer chase. Gate with `benches/snat_allocator.rs`. |
| A2-2 | `nat/source.rs` (1389) — `match_source_nat_result_for_tuple` 336 LOC + 6 responsibilities | 1389 | (B) STRUCTURAL | Extract `classify_l4_mode` enum + `allocate_pool_v4/v6` helpers. Two PRs: pure predicate extraction, then allocation-driver split. |
| A2-3 | `pkg/config/compiler_nat.go` (2529) — 5 NAT types + 4 validators + helpers fused ~37 funcs | 2529 | (A) MECHANICAL | 6-file split, pure code-motion, no behavior change. No hot-path. |
| A2-4 | `nat/destination.rs` (1088) | 1088 | (D) NEGATIVE | Cohesive DNAT lookup, under threshold, do not split |
| A2-5 | `nat/tests_*.rs` (9288 test LOC, 8 files) | — | (D) NEGATIVE | Already split per #4409, each <4000 LOC, no further action |

## Cross-cutting notes

### nat64.rs / nptv6.rs

- `nat64.rs` 2527 LOC: NAT64 forward+reverse, EH walk, frag, ICMP-embed. Responsibilities: `Nat64State` (prefix matching, pool selection, allocator reuse), `Nat64Prefix`, `translate_v6_to_v4`/`translate_v4_to_v6`, `ipv6_l4_offset_and_protocol` (EH walk), `ipv6_fragment_header`, `translate_embedded_*`, `reserve_synced_nat64_allocation`. This is cohesive — all NAT64 translation. The EH walk helpers (`ipv6_l4_offset_and_protocol`, `ipv6_is_non_first_fragment`, `ipv6_fragment_header`) are 3 small fns that could be extracted to `nat64/ipv6_ext.rs` but 2527 LOC is just over the 2000-LOC smell. Propose deferred: if next NAT64 feature adds ~200 LOC, split then (per engineering-style "refactor with new features, not after").

- `nptv6.rs` 431 LOC: small, single responsibility, no action.

- `userspace-xdp/src/lib.rs` 1541 LOC: shim, not NAT. No NAT-related classification — only DNAT map definitions (`DnatKeyV4/V6`) mirrored from `bpf/headers/xpf_maps.h`. No finding.

### Hot-path overall

- `reserve_flow` (allocator.rs:1206) + `nat_reverse_index` (session/mod.rs, not in batch but referenced) are per-new-flow. Current code is zero-alloc, lock-free bitmap CAS. Any allocator split must preserve this.
- `match_source_nat_result_for_tuple` is cold-path (session-miss) but high-frequency under SYN flood — must stay zero-alloc, no `Vec` clone.
- `DnatTable::lookup_with_counter_scoped` is cold-path (session-miss) — not hot, no cache-line concern.

### Verification matrix

| Finding | Unit tests | Bench/gate | Integration |
|---------|------------|------------|-------------|
| A2-1 | `cargo test -p userspace-dp nat::tests_pool` (79) | `cargo bench snat_allocator` — must not regress vs 2852 baseline 1.4-1.6x | `make cluster-deploy` + iperf3 23+ Gbit/s |
| A2-2 | `cargo test nat::tests_source/pool/l4_match/scope` (129) | None (cold path) | `make test-deploy` + NAT pool exhaustion test |
| A2-3 | `go test ./pkg/config -run TestCompileNAT` | `make selftest` | `make test-deploy` + config commit with dup-block (#3915) |
| A2-4 | (D) negative — existing tests unchanged | — | — |
| A2-5 | (D) negative — existing tests unchanged | — | — |
