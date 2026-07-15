# Review 039 — A1f: Screen / filter / frame / policy / appid — Monolithic audit

**Base:** f70146951583823a5ace87b0b11a2e58f46e8db9  
**Scope:** `userspace-dp/src/screen/*`, `userspace-dp/src/afxdp/frame/*`, `userspace-dp/src/afxdp/types/runtime.rs`, `userspace-dp/src/policy.rs`, `userspace-dp/src/filter/*`  
**Date:** 2026-07-08  
**Batch:** A1f — Screen / filter / frame / policy / appid

---

## File-size / shape inventory

| File | Prod LOC | Total inc. tests | Role | Verdict |
|------|----------|-----------------|------|---------|
| `screen/mod.rs` | 1540 | 1540 (+5395 tests.rs sep) | ScreenState (25+ hashmaps), orchestrator `check_packet_with_zone_id_opts` (373 lines), flood-helpers, missing-profile WARN, SYN-cookie epoch, scan/sweep dispatch, flowless path | **Moderate god-file** — already 7-way decomposed (see below), but orchestrator remains 373-line fused function + 8 per-zone HashMaps that could be grouped |
| `screen/scan.rs` | 621 prod / 1213 total | 1213 | `ScanCore<T>` generic tracker, `PortScanTracker`, `IpSweepTracker`, eviction, cleanup, pressure events, window-aware reap, 12 regression tests | **Borderline** — generic core is clean; two `T`-specialised wrappers are thin; tests are 590 lines in same file but well-organized |
| `screen/stateless.rs` | 262 | 262 | 6 side-effect-free checks (LAND, TCP-flag, ping-of-death, teardrop, icmp-fragment, source-route) | **Clean** — `#[inline]` leaf helpers, single responsibility |
| `screen/rate.rs` | 609 | 609 | `RateCounter`, `TokenBucket`, two-bucket sliding window | **Clean** — stateless counter impls |
| `screen/syn_rate.rs` | 504 | 504 | `SynRateSketch` (count-min) for per-dst / per-src sub-thresholds (#3315 / #4112) | **Clean** — isolated sketch, no ScreenState coupling except via caller |
| `screen/syncookie.rs` | 600 | 600 | `SynCookieCodec`, `SipHash24`, `SynCookieValidatedCache`, challenge/validation | **Clean** — crypto isolated per #1543 Wave-5 |
| `screen/extract.rs` | 400 | 400 | IP/TCP header parser → `ScreenPacketInfo`, IPv6 ext-header walk, frag parsing | **Clean** — allocation-free parser |
| `screen/packet.rs` | 174 | 174 | `ScreenPacketInfo`, `ScreenProfile`, `ScreenVerdict`, `ScreenParseError` | **Clean** — data defs only |
| `afxdp/frame/inspect.rs` | 1813 | 1813 (+517 inspect_tests.rs sep) | 6 IPv6 EH walkers (duplicated match arms), 5 frag predicates, 3 port parsers, 3 `term_match_extra` builders, 4 L3-declared-end helpers, 6 session-flow parsers, 3 ICMP-error-suppression helpers, `decode_frame_summary`, `try_parse_metadata` | **Monolith + copy-paste** — 6 copies of same EH match arm; 6 distinct responsibility clusters fused in one file |
| `afxdp/frame/mod.rs` | 1710 | 1710 | NAT apply v4/v6, port-rewrite, ICMP-ident rewrite, DSCP rewrite, checksum adjust, L2-rewrite classification, VLAN push/pop descriptor trick, in-place rewrite prep/apply, injected-packet builders, verify, NAT64 dispatch | **Moderate god-file** — `build/` and `rewrite/` subdirs already extracted (6 files, ~2000 LOC), but remaining 1710 LOC still mixes 5 responsibilities; largest fn `verify_built_frame_checksums` (191 lines, debug-only) |
| `afxdp/frame/wg.rs` | 1561 | 1561 | `wg_encap_frame` + `outer_physical_egress_ifindex/mtu`, `wg_peer_outer_dst`, `wg_endpoint_physical_outer_mtu`, MTU guard, source rewrite, + 600 LOC tests in same file | **Moderate** — prod ~900 LOC, tests ~650 LOC; tests should be in `wg_tests.rs` |
| `afxdp/frame/tcp.rs` | 680 | 680 + 1043 tcp_tests | TCP inspect + mutation kernels | **Clean** |
| `afxdp/frame/checksum.rs` | 984 | 984 | Incremental checksum family, zero-checksum predicates | **Clean** |
| `policy.rs` | 3598 | 3598 (+278k tests.rs) | `PolicyRule`, `PolicyState`, `CompiledApplications`, `AppCatalog` (appid), `AppScanEntry`, `PolicyRuleCounter`, `PolicyCounterStore`, `PendingPolicyHitRecord` coalescer, wildcard/global expansion, zone-pair index, `GlobalZoneScope`, default-policy sentinel, 15+ helper fns | **God-file (3598 LOC)** — mixes 4 independent responsibilities (zone-policy, appid catalog, counter store, global/wildcard expansion) |
| `filter/mod.rs` | 939 | 939 | `FilterTerm`, `Filter`, `FilterState` (15+ iface maps), `FilterAction`, `TermMatchExtra`, `CachedFilterCounters`, `ThreeColorPolicerRuntime`, counter flush helpers | **Clean module** — compiler/engine/policer already extracted to 3 submods |
| `filter/compiler.rs` | 1056 | 1056 | `parse_filter_state`, `parse_term`, prefix/port/protocol/DSCP parsing, fail-closed backstops | **Clean** |
| `filter/engine/` | ~2000 (4 files) | — | Matching, eval, cache-sensitive gating, policer, TX-selection | **Clean** — #1049 P2 split |
| `afxdp/types/runtime.rs` | 503 | 503 | `WorkerHandle`, `BindingPlan`, `WorkerContext` (16 fields, #945), `TelemetryContext`, `MirrorTargetMap`, HA lease, `ResolutionDebug`, `LearnedNeighborKey` | **Clean** — pure relocation from types/mod.rs (#68.4), no policy bypass |

**Totals:** screen 4890 prod (+5395 tests), frame 8290 prod (+19027 inc tests/prop), policy 3598, filter ~4000, runtime 503.

---

## Finding 1: (A) — `frame/inspect.rs` 1813 LOC — 6× duplicated IPv6 EH walker — mechanical deduplication, not responsibility split

**Severity:** Medium (maintainability / correctness — drift risk)  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL — extract single walker, no behavior change  
**Dedup:** Not filed elsewhere. #4517 added Mobility/HIP/Shim6 arms to all walkers in one PR; #2150 documents 5 L2 parsers + 3 IPv6 walkers as known drift canaries with tests — this finding proposes the actual dedup PR-2 that #2150 deferred. #4418 raised `MAX_CLEANUP_WINDOW_MICROS` — unrelated. Distinct.

### Evidence

`inspect.rs` contains 6 functions that each walk the IPv6 EH chain with byte-for-byte identical match arms (`0 | 43 | 60 | 135 | 139 | 140 | 253 | 254`, `51` AH, `44` Fragment, `59` No-Next-Header). Each function repeats the same 15-line match:

```rust
// frame_l4_offset (line 71), packet_rel_l4_offset (134), packet_rel_l4_offset_and_protocol (197),
// ipv6_is_non_first_fragment (289), ipv6_is_any_fragment (374), is_non_first_fragment dispatch
match protocol {
    0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
        let opt = frame.get(offset..offset+2)?;
        protocol = opt[0];
        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
        ...
    }
    51 => { /* AH (len+2)*4 */ }
    44 => { /* Fragment 8 bytes */ }
    59 => return None,
    _ => return Some(offset),
}
```

Count: 6 copies of the 8-type generic-EH arm + AH + Fragment + NoNextHeader terminal. A seventh copy exists in `screen/extract.rs` (IPv6 walker), an eighth in `nat64.rs`, a ninth in `icmp_embed/parse.rs` — total 9 walkers across 4 files (documented in `frame/README.md` "Canonical L2 / IPv6 parse contract").

Adding a new EH type (e.g. #4517 added 5 types) requires touching 9 sites. #4517 did touch all 9 (verified via `git show`), but the drift canary test (`l2_offset_canary_all_parsers_agree`, `ipv6_walk_canary_learning_agrees_with_forwarding`, `nat64_l2_offset_canary`) only covers L2 offset and one IPv6 walk pair — not all 9 EH-type sets. If a future PR adds a type to 8 of 9 walkers, the 9th silently diverges (IDS evasion — the pre-#4517 bug: `HOP → MOBILITY → FRAGMENT → TCP` classified as proto=135, hiding SYN from screens).

Beyond the walkers, `inspect.rs` mixes 6 responsibility clusters:

| Cluster | Functions | LOC |
|---------|-----------|-----|
| EH walk + L4 offset | `frame_l4_offset`, `packet_rel_l4_offset`, `packet_rel_l4_offset_and_protocol`, MAX_IPV6_EXT_HEADERS const | ~200 |
| Fragment predicates | `ipv4_is_non_first_fragment`, `ipv6_is_non_first_fragment`, `is_non_first_fragment`, `ipv4_is_any_fragment`, `ipv6_is_any_fragment`, `is_any_fragment` | ~200 |
| L3/L4 port pipeline | `ipv4_declared_l3_end`, `ipv6_declared_l3_end`, `declared_l3_end`, `parse_flow_ports`, `icmp_identifier_bearing`, `meta_icmp_identifier_bearing` | ~350 |
| Filter match-extra builders | `term_match_extra_from_frame`, `term_match_extra_from_frame_fwd`, `term_match_extra_from_meta` + `is_fragment` + truncated-ICMP fail-closed | ~300 |
| ICMP-error suppression | `dest_is_multicast_or_broadcast`, `dest_is_directed_broadcast`, `src_is_directed_broadcast`, `source_is_invalid_for_icmp_error`, `l2_dst_is_group_or_broadcast`, `v4_addr_is_directed_broadcast`, `neighbor_ip_is_learnable` | ~250 |
| Session-flow parsers | `parse_session_flow_from_bytes`, `parse_session_flow_from_frame`, `parse_session_flow_from_meta`, `parse_ipv4_session_flow_from_frame`, `l3_session_flow_from_meta`, `frame_is_non_first_fragment`, fabric/zone decode, `decode_frame_summary` | ~500 |

Each cluster has distinct callers: EH walkers — screen + forwarding + NAT + NAT64 + filter; fragment predicates — NAT skip + filter `is-fragment` + session-flow gate; port pipeline — session lookup + flow-cache; filter builders — filter eval; ICMP suppression — reject/PTB replies; session-flow — conntrack.

### Proposed decomposition

```
frame/
  ipv6_ext.rs          — ONE generic EH walker: fn walk_ipv6_ext_headers<F>(packet: &[u8], mut visit: F) -> WalkResult
                         + MAX_IPV6_EXT_HEADERS const + EH_TYPE_SET const (single SSOT for 0|43|60|135|139|140|253|254)
                         WalkResult = Continue { next_proto, next_offset } | Terminal { l4_offset, protocol }
                                    | FragmentHeader { offset_bytes, is_non_first, is_any }
                                    | Truncated | NoNextHeader | TooManyHeaders
                         6 existing walker fns become 1-2 line wrappers:
                           frame_l4_offset(frame) -> walk(...).l4_offset()
                           ipv6_is_non_first_fragment(packet) -> walk(...).is_non_first_fragment()
                           ipv6_is_any_fragment(packet) -> walk(...).is_any_fragment()
                         All 9 walkers in 4 files import EH_TYPE_SET from here — single addition point.
  frag.rs              — ipv4_is_non_first_fragment, ipv4_is_any_fragment, is_non_first_fragment, is_any_fragment,
                         frame_is_non_first_fragment, v4_addr_is_directed_broadcast helper (shared by dest + src directed-broadcast)
  l3_declared.rs       — ipv4_declared_l3_end, ipv6_declared_l3_end, declared_l3_end, parse_flow_ports,
                         icmp_identifier_bearing, meta_icmp_identifier_bearing
  filter_match.rs      — term_match_extra_from_frame, term_match_extra_from_frame_fwd, term_match_extra_from_meta
  icmp_suppress.rs     — dest_is_multicast_or_broadcast, dest_is_directed_broadcast, src_is_directed_broadcast,
                         source_is_invalid_for_icmp_error, l2_dst_is_group_or_broadcast, neighbor_ip_is_learnable
  flow_parse.rs        — parse_session_flow_from_bytes, parse_session_flow_from_frame, parse_session_flow_from_meta,
                         parse_ipv4_session_flow_from_frame, l3_session_flow_from_meta, frame_is_non_first_fragment,
                         parse_zone_encoded_fabric_ingress*, parse_packet_destination_from_frame, metadata_tuple_complete,
                         decode_frame_summary, try_parse_metadata, authoritative_forward_ports helpers
```

`inspect.rs` becomes a re-export hub (or is deleted — callers import from `frame::ipv6_ext::`, `frame::frag::`, etc.). `mod.rs` re-exports preserve `pub(in crate::afxdp)` / `pub(super)` visibility.

Mechanical: every wrapper is `#[inline]` and monomorphizes to identical codegen — the EH walk is already `#[inline]` today. The walker function's match arm is emitted once per generic instantiation, but `#[inline(always)]` on the walker + concrete visitor closures folds to same as today (the optimizer sees through the visitor because it's a single-use closure).

This is **PR-2 of #2150** — the doc already describes this exact split (`afxdp/frame/parse/` tree), gated on canaries staying green. The canaries are green today; this PR closes the loop.

### Hot-path preservation

- EH walk is on the packet hot path (every IPv6 packet). The single-walker extraction must be `#[inline(always)]` so the per-packet call does not add a call frame. Verify via `cargo show-asm` or by checking `perf stat` cycle count — expect byte-identical codegen (the walker already inlines today; adding one level of indirection with `#[inline(always)]` preserves it).
- No new allocation: walker takes `&[u8]` and returns `Option<(usize, u8)>` or a small enum — same as today.
- No new branch: the match arm set is unchanged, just centralized. Branch predictor sees same pattern (same `protocol` dispatch order). ENUM + match on `WalkResult` adds one predictable branch on cold error paths (Truncated/TooManyHeaders), not on hot Success path.

### Tests / gate

- `make test` (includes `frame/inspect_tests.rs` 517 LOC + `frame/tests.rs` 8290 LOC + proptest `prop_tests/inspect.rs` parse no-panic/bounds/round-trip 512 cases) — all must pass.
- Existing canary tests must stay green: `l2_offset_canary_all_parsers_agree`, `ipv6_walk_canary_learning_agrees_with_forwarding`, `nat64_l2_offset_canary` — they pin the contract this PR preserves.
- Add one new canary: `eh_type_set_is_single_source_of_truth` — asserts `frame::ipv6_ext::EH_TYPE_SET == screen::extract::EH_TYPE_SET == nat64::EH_TYPE_SET == icmp_embed::EH_TYPE_SET` (or that all import from one const). Prevents future partial update.
- `cargo test --release prop_tests::` (parse-round-trip valid-packet generator still agrees with new walker).
- `make cluster-deploy` + `iperf3` smoke — IPv6 transit with EH chains (1 EH, Fragment, multi-EH) must not regress.

### Why it matters

The duplicated 8-type EH arm is the single highest-drift-risk pattern in `userspace-dp`. #4517 proved it: 5 new EH types required touching 9 sites atomically. Any future EH type (e.g. new RFC) requires the same 9-site sync. The single-const `EH_TYPE_SET` eliminates this class of IDS-evasion drift entirely — one const, one match arm, every walker reads it.

Separate dimension: `inspect.rs` at 1813 LOC violates the project's "no monolithic files" rule (modularity discipline: ~2000 LOC soft threshold, ~3000 hard). At 1813 it is below hard but above the "split before adding new logic" threshold. Every new filter-match predicate (`flex_l4`, `is_fragment`, `icmp-type`) adds another `term_match_extra_*` builder to this file, growing it further.

### Fix direction

1. Create `frame/ipv6_ext.rs` with `EH_TYPE_SET: &[u8]` (or const array) + `walk_ipv6_ext_headers(packet: &[u8], max: usize, visitor) -> WalkResult`. Move `MAX_IPV6_EXT_HEADERS` here (SSOT).
2. Update `frame/inspect.rs` walkers to call `walk_ipv6_ext_headers`; update `screen/extract.rs`, `nat64.rs`, `icmp_embed/parse.rs` to import `EH_TYPE_SET` / `MAX_IPV6_EXT_HEADERS` from `frame::ipv6_ext`.
3. Incrementally extract frag / l3_declared / filter_match / icmp_suppress / flow_parse clusters in follow-up PRs (or same PR if <400 LOC moved per cluster). Each cluster extraction is mechanical — move functions, add `mod` in `frame/mod.rs`, re-export via `pub(in crate::afxdp) use cluster::*;` to preserve existing call sites.
4. Add `eh_type_set_is_single_source_of_truth` canary test.

### Labels

`refactor`, `modularity`, `ipv6`, `eh-walk`, `dedup`, `perf-neutral`

### Dedup note

- **#2150 PR-1** — closed the L2-parser and IPv6-walker drift canaries but deferred the full unification to **PR-2** (`afxdp/frame/parse/` tree). This finding IS that PR-2 — not a duplicate, but the planned next phase. Do not re-file the canary work; file the walker dedup.
- **#4517** — added Mobility/HIP/Shim6/experimental EH types to all 9 walkers. Mechanical but proved the drift risk. Not a dedup target.
- **#2292** — fail-CLOSED at EH bound (`MAX_IPV6_EXT_HEADERS`). Correctness fix, not dedup. Distinct.
- **#986 / #988** — planned `frame/` splits (historical). Overlap in intent but not in concrete filing — this report provides the measured 6-cluster breakdown that those tracking issues lack.

---

## Finding 2: (A) — `policy.rs` 3598 LOC — 4 independent responsibilities fused — AppCatalog / counter-store / policy-rule could be separate modules

**Severity:** Medium (modularity debt)  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL — file split, no behavior change  
**Dedup:** #4421 was filed as "policy.rs god-file (3600 LOC)" — this overlaps but provides the NEW concrete 4-way split map that #4421 lacked + quantifies the AppCatalog isolation opportunity (which #4421 did not mention). If #4421 already covers the full split, mark this as supplementary detail for that issue rather than a new filing. Do not re-file the god-file claim; file only the NEW actionable split.

### Evidence

`policy.rs` is 3598 LOC (well above the ~3000 hard threshold). It contains 4 responsibilities with almost no cross-coupling:

| Responsibility | Types | LOC | Depends on | Used by |
|---|---|---|---|---|
| **Zone-policy evaluation** | `PolicyState`, `PolicyRule`, `ZonePairKey`, `GlobalZoneScope`, `JUNOS_GLOBAL_ZONE_ID`, `JUNOS_HOST_ZONE_ID`, `PolicyAction`, `DEFAULT_POLICY_SENTINEL_ID`, `ZONE_ID_RESERVED_MIN`, `zone_pair_key`, `zone_name_to_id_from_snapshot`, `build_global_zone_scope`, `resolve_policy_zone_id`, `parse_policy_state*`, `evaluate_policy*`, `evaluate_junos_host_policy*`, `try_match_rule`, `rule_l3_matches`, `note_skipped_frag_deny`, `apply_frag_deny_override`, `configured_zone_pairs`, `stable_policy_rule_id` | ~2200 | `PrefixSetV4/V6`, `BookEntry`, `ApplicationMatch`, `PolicyCounterStore` (via Arc) | `afxdp/poll_descriptor`, `session/sync`, local-delivery gate |
| **AppID catalog** | `AppCatalog`, `AppProtoEntries`, `AppScanEntry`, `AppCatalogEntry` (imported) | ~350 | Nothing inside policy.rs (pure 5-tuple → app_id map) | `afxdp/poll_descriptor`, `event_stream`, `filter/log` — called via `AppCatalog::lookup_directional` / `lookup_forward` / `lookup_admitted` |
| **Counter store + coalescer** | `PolicyRuleCounter`, `PolicyCounterRegistry`, `PolicyCounterStore`, `PendingPolicyHitRecord`, `POLICY_HIT_FLUSH_PACKETS`, `record_policy_hit_counter`, `flush_recorded_policy_hit_counters`, `flush_pending_policy_hit_record`, `DEFAULT_POLICY_COUNTER_RULE_ID`, `DEFAULT_POLICY_COUNTER_IDX` | ~400 | `PolicyRule` (counter Arc cloned at rule build) | `afxdp/poll_descriptor` fast path, `show security policies hit-count` |
| **Application matching** | `ApplicationMatch`, `PortRange`, `CompiledApplications`, `ProtoTerms`, `port_ranges_match`, `parse_applications`, `parse_port_u16` | ~600 | `PolicyRule` (compiled at build time) | `policy.rs` itself only (via `try_match_rule` → `CompiledApplications::matches`) |

Cross-coupling inventory:

- `AppCatalog` has ZERO dependency on `PolicyState` / `PolicyRule` / `PolicyCounterStore`. It is constructed from `AppCatalogEntry` slices (from `ConfigSnapshot`) and queried via `(protocol, src_port, dst_port, is_reverse) -> app_id`. It could live in `app_catalog.rs` or `appid.rs` with zero import changes to `policy.rs` itself.
- `PolicyCounterStore` / `PolicyRuleCounter` / coalescer: the store is a `Arc<Mutex<FxHashMap<String, Arc<PolicyRuleCounter>>>>` keyed by `stable_policy_rule_id`. `PolicyRule` holds one `Arc<PolicyRuleCounter>` (cloned from store at build time). The coalescer is thread-local (`PENDING_POLICY_HIT_RECORD`) with `POLICY_HIT_FLUSH_PACKETS = 64` batching — identical pattern to `filter::PendingFilterCounterRecord`. This entire subsystem could live in `policy/counters.rs` with 3 re-exports (`PolicyRuleCounter`, `PolicyCounterStore`, `record_policy_hit_counter` / `flush_recorded_policy_hit_counters`).
- `CompiledApplications` / `ProtoTerms` / `PortRange` / `parse_applications`: tightly coupled to `PolicyRule` (built inside `parse_policy_state_with_counters`), but could live in `policy/app_match.rs` as a submodule — `PolicyRule::compiled_apps` is the only consumer.

File already uses `#[path = "policy_snapshot_error.rs"] mod snapshot_error;` — the pattern for submodule extraction is established.

The `policy_tests.rs` sidecar is 278k lines (6x larger than `policy.rs` itself) — it lives in its own file (correct per project pattern), but its tests for `AppCatalog` (15 tests, `cat_entry`, `lookup_directional`, `lookup_forward`, `lookup_admitted`) could move to `app_catalog.rs` co-located tests when that module is extracted.

`screen/mod.rs` count (Finding 1 context): `AppCatalog` is cited in the batch as "policy-related .rs files" — it is NOT filter, NOT screen, NOT frame, but lives inside `policy.rs`. A reader looking for "appid matching" naturally searches `appid.rs` / `app_catalog.rs` — not `policy.rs:1065`.

### Proposed decomposition

```
policy/
  mod.rs              — re-export hub + `PolicyState`, `PolicyRule`, zone-pair / wildcard / global index, `evaluate_policy*`, `try_match_rule`, `configured_zone_pairs`, constants (ZONE_ID_*, DEFAULT_POLICY_*, JUNOS_*), helper fns (zone_pair_key, zone_name_to_id_from_snapshot, stable_policy_rule_id, rule_has_unrepresentable_address_sentinel, parse_legacy_address_set, parse_v3_literal_set, parse_book_prefix_into, resolve_book_idxs)
  app_catalog.rs      — AppCatalog, AppProtoEntries, AppScanEntry, from_snapshot, lookup_directional/forward/admitted, is_empty
                      — 15 appid tests move here (mod tests under #[cfg(test)])
  counters.rs         — PolicyRuleCounter, PolicyRuleCounterStatus, PolicyCounterRegistry, PolicyCounterStore,
                        PendingPolicyHitRecord, POLICY_HIT_FLUSH_PACKETS, record_policy_hit_counter, flush_recorded_policy_hit_counters,
                        flush_pending_policy_hit_record, DEFAULT_POLICY_COUNTER_RULE_ID, DEFAULT_POLICY_COUNTER_IDX, generation helpers
  app_match.rs        — ApplicationMatch, PortRange, CompiledApplications, ProtoTerms, parse_applications, parse_port_u16, port_ranges_match,
                        has_l4_constrained_term (used by fragment fail-closed guard)
  snapshot_error.rs   — already extracted (SnapshotIntegrityError) — no change
```

`policy.rs` (root) becomes `policy/mod.rs` (or stays as `policy.rs` with `mod app_catalog; mod counters; mod app_match;` — Rust allows sibling `policy/` dir with `policy.rs` as parent module). The `[path = "policy_snapshot_error.rs"] mod snapshot_error;` pattern continues.

Mechanical steps:

1. Create `policy/app_catalog.rs` — move `AppCatalog` + impl + `AppProtoEntries` + `AppScanEntry` + `#[cfg(test)] mod tests` (15 appid tests from `policy_tests.rs`). No behavior change — pure move.
2. Create `policy/counters.rs` — move counter store + coalescer + generation logic + 2 `#[cfg(test)]` helpers (`clear_security_policies_hit_count_*`). Re-export `PolicyRuleCounter`, `PolicyCounterStore` via `pub(crate) use counters::*;`.
3. Create `policy/app_match.rs` — move `ApplicationMatch` + `PortRange` + `CompiledApplications` + `ProtoTerms` + parse helpers. Keep `impl CompiledApplications::matches` here (it is the hot-path predicate). No call-site change — `policy.rs` already imports via `use super::*` in tests.
4. Update `policy.rs` (now `policy/mod.rs`) imports: `mod app_catalog; mod app_match; mod counters; pub(crate) use app_catalog::AppCatalog; pub(crate) use counters::{PolicyRuleCounter, PolicyCounterStore, ...};` etc.

Each step is a pure move + re-export — no rename, no signature change, no logic change. `cargo test -- policy` must pass after each step.

### Hot-path preservation

- `AppCatalog::lookup_directional` is on the packet cold path (session-miss only, guarded by `policy_catalog.is_empty()` check at poll_descriptor — NOT per-packet on established flows). Moving it to a submodule does not change its `#[inline]` status or monomorphization. No hot-path impact.
- `CompiledApplications::matches` IS on the hot path (called from `try_match_rule` → `evaluate_policy_result_l3_aware`, which is the session-miss classification). It is `#[inline]` today and stays `#[inline]` in the new submodule — same monomorphization, same inlining decision by LLVM (the function body is unchanged, only its defining module path changes from `crate::policy` to `crate::policy::app_match`).
- `record_policy_hit_counter` is on the established fast path (every packet of an admitted flow). It is `#[inline(always)]` and uses a thread-local `PENDING_POLICY_HIT_RECORD`. Moving it to `policy/counters.rs` with `pub(crate)` visibility preserves the `#[inline(always)]` guarantee — the `thread_local!` lives in the same module as the `record_*` fn, so access is still direct.
- `PolicyCounterStore` / `PolicyRuleCounter` atomics: no change — `Arc<PolicyRuleCounter>` type, `AtomicU64` fields, `Ordering::Relaxed` all unchanged. No new lock, no new contention.
- Build-time `parse_policy_state_with_counters`: still constructs `AppCatalog` from `AppCatalogEntry` slices and `PolicyCounterStore` from rule_ids — call sites unchanged (same function signature, just re-exported).

### Tests / gate

- `make test` — includes `policy_tests.rs` (278k lines, ~200 tests) + appid-specific tests (`lookup_directional`, `lookup_forward`, `lookup_admitted`, `app_catalog_*`, fail-on-revert appid-direction test #3321, appid-overlap specificity #3612).
- After each extraction step: `cargo test -p userspace-dp --lib -- policy` (fast, <10s) — must pass.
- After full split: `make test-rust` (full `userspace-dp` cargo suite) — must pass.
- `make cluster-deploy && ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0 && iperf3 -P 16 -t 10` — policy + appid + counter telemetry must not regress (hit-count still increments per packet on established flows via `record_policy_hit_counter` coalescer).
- No new tests required (mechanical move). Optionally add a `policy/app_catalog.rs` `#[cfg(test)] mod tests` with the 15 appid tests moved from `policy_tests.rs` to keep them co-located per project pattern (`tx/`, `cos/` layout).

### Why it matters

`policy.rs` at 3598 LOC violates the "no monolithic files" rule (hard threshold ~3000). It is the single largest non-test prod file in `userspace-dp/src/` (larger than `screen/mod.rs` at 1540). Every new policy feature (wildcard zones #3090, `junos-global` scoped #3148, `junos-host` self-traffic #3019, fragment-association fail-closed #4569, appid directional #3321, appid overlap specificity #3612, counter generation #3448/#3782) adds to this single file, because there is no natural seam to add elsewhere. A contributor fixing an appid bug must read 3598 LOC of zone-policy + wildcard + global + counter logic to find the 350 LOC appid catalog. The file already has a `SessionTable`-style hotspot — largest fn `parse_policy_state_with_counters` (558 LOC) + `evaluate_policy_result_l3_aware` (286 LOC) + `rule_l3_matches` (157 LOC) + `evaluate_junos_host_policy_l3_aware` (136 LOC) — 4 god functions in one file.

The `AppCatalog` isolation is the highest-value slice: it has zero coupling to the rest of `policy.rs`, is searched for under `appid.rs` (not `policy.rs`), and its 15 tests are orphaned in `policy_tests.rs` (278k lines) where they are hard to discover. Moving it first gives an immediate LP win — `mod tests` co-located with `AppCatalog` follows the `tx/` and `cos/` layout that the project pattern calls out as exemplary.

### Fix direction

Same as "Proposed decomposition" above — 3 PRs, ordered by coupling (lowest first = lowest risk):

1. **PR-1: `AppCatalog` → `policy/app_catalog.rs`** — pure move, 350 LOC, zero cross-coupling, 15 tests move with it. Immediate LP win.
2. **PR-2: Counter store + coalescer → `policy/counters.rs`** — 400 LOC, thread-local + Arc sharing preserved, `#[inline(always)]` preserved. No call-site signature change.
3. **PR-3: `CompiledApplications` / `PortRange` / `ApplicationMatch` → `policy/app_match.rs`** — 600 LOC, `matches` stays `#[inline]`, `has_l4_constrained_term` moves with it. `policy/mod.rs` retains `PolicyState` / `PolicyRule` / `evaluate_policy*` / zone/wildcard/global.

Each PR keeps `policy.rs` buildable (or renames to `policy/mod.rs` in PR-1) and `cargo test -- policy` green at every step.

### Labels

`refactor`, `modularity`, `policy`, `appid`, `mechanical`

### Dedup note

- **#4421 — SessionTable / PolicyState god-struct** — already filed. This finding is the concrete 4-way split map for the `policy.rs` half of that issue, plus the NEW observation that `AppCatalog` has zero coupling and is the lowest-risk first slice. If #4421 is closed as "policy split done", this finding is supplementary detail for the counter + app_match remaining slices.
- **#4412 / #4421** — policy wildcard/global expansion (`from_any_index`, `to_any_index`, `both_any_indices`, `global_indices`, `concrete_zone_ids`) — those are correctness fixes, not modularity. This finding does not re-report them; it preserves them as hard constraints on any split (wildcard/global tiers must stay in `policy/mod.rs` because they are part of the `evaluate_policy*` dispatch — not separable).
- **#1401 — appid implementation** — feature history, not modularity debt. Distinct.

---

## Finding 3: (D) — Well-decomposed subsystems — negative findings (no action needed)

**Severity:** None (negative confirmation)  
**Confidence:** High  
**Refactor class:** (D) — clean code confirmed, no action  
**Dedup:** None — these were checked and confirmed sound to avoid duplicate filings.

### `filter/` — exemplary decomposition (negative)

`filter/mod.rs` is 939 LOC — below the 2000 LOC soft threshold. The heavy lifting is already split:

| Submodule | LOC | Role |
|-----------|-----|------|
| `compiler.rs` | 1056 | `parse_filter_state`, `parse_term`, protocol/port/DSCP/addr/flex parsing, fail-closed backstops (15+ `SnapshotIntegrityError` variants) |
| `engine/mod.rs` + `matching.rs` + `eval.rs` + `cache_sensitive.rs` + `policer.rs` + `tx_selection.rs` | ~2000 | Per-packet matching (`nets_match_v4/v6`, `port_match`, `per_packet_l4_matches`, `flex_matches`), eval loop (first-match-wins with `continue_term` fall-through #2544), cache-sensitive gating (#1431), three-color policer metering (#2544/#4566 dedup), TX-selection |

This is the target pattern for `policy.rs` and `frame/inspect.rs` (Finding 1/2). The `#1049 P2` split (compiler + engine + policer) is complete and mechanical. `FilterState`'s 15+ per-iface maps (`iface_filter_v4`, `iface_filter_v4_fast`, `iface_filter_v4_affects_tx_selection`, `has_input_tx_selection_v4`, `iface_filter_v4_has_per_packet_l4_match`, etc.) are correctly maintained in `compiler.rs` and consumed via `FilterState` accessors — no cross-file field coupling beyond the struct definition.

`filter/policer.rs` (504 LOC) is a clean rate-limiter impl (token bucket + three-color states) with no `FilterState` coupling.

**No action.** Use as template for `policy.rs` extraction.

### `screen/` submodule decomposition — well-decomposed (negative with one note)

`screen/mod.rs` is 1540 LOC (below hard threshold, above soft). But it is already 7-way decomposed per #1543 Wave-5:

| Submodule | LOC | Role | Verdict |
|-----------|-----|------|---------|
| `packet.rs` | 174 | Data defs only | Clean |
| `stateless.rs` | 262 | 6 `#[inline]` DROP-or-None helpers | Clean — branch-predictor friendly (each check is a single branch) |
| `rate.rs` | 609 | `RateCounter` + `TokenBucket` | Clean |
| `syn_rate.rs` | 504 | `SynRateSketch` (count-min) | Clean — sketch is allocator-free at increment time |
| `syncookie.rs` | 600 | Crypto (SipHash24, codec, validated cache) | Clean — auditable in isolation |
| `scan.rs` | 621 prod / 1213 total | `ScanCore<T>` generic + bounded eviction + window-aware cleanup | Borderline size but generic core is clean; see Finding 4 note below |
| `extract.rs` | 400 | Header parser | Clean |

The remaining `mod.rs` is the orchestrator: `ScreenState` (25+ HashMaps for 8 counter/sketch types + missing-profile WARN + SYN-cookie epoch + scan/sweep + alarm) + `check_packet_with_zone_id_opts` (373 lines, fuses 16 checks in order) + `check_flowless_screens_opts` (103 lines) + `scan_sweep_drop_on_new_flow` (75 lines) + `validate_syn_cookie_ack_on_session_miss` (63 lines) + 3 flood helpers (`icmp_flood_drop`, `udp_flood_drop`) + `maybe_warn_missing_profile` + `scan_cleanup_floors` + SYN-cookie epoch helpers.

The 373-line `check_packet_with_zone_id_opts` is large but NOT a god-function in the classic sense — it is a sequential pipeline of `if cond { return Drop }` with copy-out of scalars to release the `self.profiles` borrow before `&mut self` sketch calls (documented via NLL comments). Each flood check could be a separate helper (`check_icmp_flood`, `check_udp_flood`, `check_syn_flood_dst`, `check_syn_flood_aggregate`, `check_syn_flood_src`, `check_syn_flood_alarm`) — but those helpers already exist (`icmp_flood_drop`, `udp_flood_drop`) and the SYN-flood path is intentionally inlined to avoid borrow-checker gymnastics (5 `get_mut` on disjoint HashMap fields in sequence — extracting to helpers would require passing 5 `&mut FxHashMap` arguments or restructuring `ScreenState` into field groups).

**One note for a future PR (not filed here):** `ScreenState`'s 8 per-zone `FxHashMap<String, *>` fields (`icmp_counters`, `udp_counters`, `syn_counters`, `syn_off_attack_buckets`, `icmp_dst_sketch`, `udp_dst_sketch`, `syn_dst_sketch`, `syn_src_sketch`, plus `syn_cookie_active_until_secs`, `syn_cookie_standby_ack_counters`, `syn_cookie_profile_gen`, `missing_profile_refs`, `missing_profile_warn_counters`, `syn_alarm_last_emit_sec`) could be grouped into 3 sub-structs:

```rust
struct FloodState {
    icmp_counters: FxHashMap<String, TokenBucket>,
    udp_counters: FxHashMap<String, TokenBucket>,
    syn_counters: FxHashMap<String, RateCounter>,
    syn_off_attack_buckets: FxHashMap<String, TokenBucket>,
    icmp_dst_sketch: FxHashMap<String, SynRateSketch>,
    udp_dst_sketch: FxHashMap<String, SynRateSketch>,
}
struct SynFloodState {
    syn_dst_sketch: FxHashMap<String, SynRateSketch>,
    syn_src_sketch: FxHashMap<String, SynRateSketch>,
    syn_alarm_last_emit_sec: FxHashMap<String, u64>,
    syn_cookie_active_until_secs: ...,
    syn_cookie_standby_ack_counters: ...,
    syn_cookie_codec: Option<SynCookieCodec>,
    syn_cookie_validated: SynCookieValidatedCache,
    syn_cookie_profile_gen: ...,
}
struct ScanState {
    port_scan: PortScanTracker,
    ip_sweep: IpSweepTracker,
    last_cleanup_secs: u64,
}
```

This would make `check_packet_with_zone_id_opts`'s 5 `get_mut` calls borrow disjoint sub-structs instead of disjoint HashMap fields — cleaner borrow story, no behavior change. But it is (B) low-priority mechanical cleanup, not blocking, and would touch every `ScreenState` method. Not filed separately here — tracked as a "consider during next screen feature" note.

**No new finding filed.** The 7-way split is exemplary; `stateless.rs` / `rate.rs` / `syn_rate.rs` / `syncookie.rs` / `packet.rs` / `extract.rs` are clean. `scan.rs` is borderline but has clean generic core (see below). Do not re-file screen as a monolith.

### `frame/` submodule decomposition — partial, moving in right direction (negative with note)

`frame/mod.rs` is 1710 LOC but has already extracted 3 subdirs:

- `frame/build/` (6 files, ~1200 LOC) — copy builders for IPv4/IPv6, frame length calc, MTU trim (`trim_l3_payload`), VLAN tag handling — extracted per #1352.
- `frame/rewrite/` (4 files, ~800 LOC) — `apply_rewrite_descriptor` orchestrator + per-AF helpers (`rewrite/ipv4.rs`, `rewrite/ipv6.rs`) — extracted per #1352.
- `frame/prop_tests/` (3 files, ~600 LOC) — proptest differential harness — gated on `cfg(all(test, not(miri)))`.

What remains in `frame/mod.rs` is 5 responsibility clusters that could be follow-up extractions (not filed here because `build/` and `rewrite/` PRs are still settling):

1. **NAT apply** (`apply_nat_ipv4` 97 LOC, `apply_nat_ipv6` 133 LOC, `apply_nat_port_rewrite` 63 LOC, `apply_nat_icmp_identifier_rewrite` 64 LOC, `adjust_l4_checksum_port` 38 LOC, `enforce_expected_ports` 47 LOC, `enforce_expected_ports_at` 40 LOC, `restore_l4_tuple_from_meta` 25 LOC) — ~550 LOC, all NAT-specific, zero frame-build coupling. Could be `frame/nat_apply.rs`.
2. **Injected-packet builders** (`build_injected_ipv4` 67 LOC, `build_injected_ipv6` 52 LOC, `build_injected_packet` dispatch) — ~130 LOC, cold path (RPM / inject tests only).
3. **DSCP rewrite** (`apply_dscp_rewrite_to_frame` 38 LOC) — standalone, could live in `frame/dscp.rs` or `frame/checksum.rs`.
4. **Checksum verification** (`verify_built_frame_checksums` 191 LOC, `CSUM_VERIFIED_TOTAL` atomics) — debug/test-only (`cfg(feature = "debug-log")` + `eprintln!`), not hot path, bloats `mod.rs`.
5. **L2 rewrite prep** (`RewritePrep`, `RewriteEthParams`, `descriptor_view_in_same_umem_frame`, `classify_in_place_l2_rewrite`, `rewrite_prepare_eth_*`, `rewrite_apply_v4`, `rewrite_apply_v6`, `rewrite_forwarded_frame_in_place`) — ~300 LOC, in-place VLAN push/pop descriptor trick.

None of these warrant a new issue today — they are post-#1352 staging candidates. The immediate priority is Finding 1 (`inspect.rs` EH walker dedup), which has correctness implications (IDS evasion drift).

**No new finding filed** for `frame/mod.rs` residual or `frame/wg.rs` test co-location (600 LOC tests in same file — should move to `frame/wg_tests.rs` per project pattern, but low priority).

### `scan.rs` window-aware cleanup + eviction — clean decomposition (negative)

`scan.rs` is 1213 LOC total (621 prod after removing tests). Structure:

- `ScanCore<T>` generic tracker (350 LOC prod) — single source of truth for bound/eviction/pressure/cleanup across both port-scan and IP-sweep.
- `PortScanTracker` thin wrapper (50 LOC) — `check` + `cleanup` + pressure accessors.
- `IpSweepTracker` thin wrapper (50 LOC) — same.
- Constants + test helpers (150 LOC).
- Tests (590 LOC) — 12 tests including fail-on-revert slow-scan evasion (#4418) and window-aware cleanup survival (#4379) — exemplary regression pins.

This is the clean extraction pattern: generic core + thin wrappers + co-located tests. The `per_zone_count` O(1) optimization (#2234) and `least-suspicious` eviction (#4418) are documented and tested with fail-on-revert. No action.

### Summary of all findings

| # | Severity | Class | Module | Summary | Action |
|---|----------|-------|--------|---------|--------|
| 1 | Medium | (A) Mechanical | `afxdp/frame/inspect.rs` (1813) + `screen/extract.rs` + `nat64.rs` + `icmp_embed/parse.rs` | 6× duplicated IPv6 EH walker match arm (`0|43|60|135|139|140|253|254` + AH + Fragment) across 9 sites in 4 files; new EH type requires 9-site sync — #4517 proved it, #2150 deferred PR-2 | Open new issue: "frame: deduplicate IPv6 EH walker into single SSOT `EH_TYPE_SET` + `walk_ipv6_ext_headers` helper (PR-2 of #2150)" |
| 2 | Medium | (A) Mechanical | `policy.rs` (3598) | 4 independent responsibilities fused (zone-policy 2200 LOC + appid catalog 350 LOC + counter store 400 LOC + app matching 600 LOC); AppCatalog has ZERO coupling to PolicyState and is searched under `appid.rs` not `policy.rs` | Feed into existing #4421 as supplementary detail (or open new issue if #4421 is closed): "policy: extract AppCatalog / counters / app_match into policy/*.rs" — PR-1 (AppCatalog) is zero-risk first slice |
| 3 | None | (D) Negative | `filter/` (compiler/engine/policer), `screen/` (stateless/rate/syn_rate/syncookie/extract/packet), `frame/` (checksum/tcp/wg/build/rewrite), `scan.rs` generic core, `afxdp/types/runtime.rs` | Well-decomposed subsystems — filter 3-way split (#1049), screen 7-way split (#1543), frame build/rewrite extraction (#1352), scan generic core, runtime pure relocation | No action — use as template; notes on ScreenState field grouping + frame/mod.rs NAT-apply residual tracked as low-priority follow-ups |

---

## Labels

- `modularity` `refactor` `mechanical` (findings 1, 2)
- `ipv6` `eh-walk` `dedup` `perf-neutral` (finding 1)
- `policy` `appid` `no-action` (finding 2 supplementary, finding 3)
- `no-action` (finding 3)

---

## Dedup note

- **#4421 — PolicyState / SessionTable / Policy god-struct** — already filed as 3598 LOC god-file. Finding 2 here does NOT re-file the god-file claim — it provides the NEW concrete 4-way split map (zone-policy / appid catalog / counter store / app matching) + the AppCatalog zero-coupling observation that #4421 did not quantify. If #4421 is open, attach Finding 2 as supplementary detail. If #4421 is closed as "policy split done", open a new narrow issue for the remaining app_match + counters slices.
- **#4399 P5 / #4438 — NAT reverse-index 1:N bucket invariant** — correctness, not modularity. This report preserves it as a hard constraint (no proposal touches NAT indexes).
- **#2150 PR-1 / #4517 / #2292 / #2146 / #2189 / #4543 / #4533** — all IPv6 EH / L2 / parse fixes. Finding 1 is the planned PR-2 deduplication that #2150 explicitly deferred (full unification onto one canonical walker). Not a re-file of any fix — it is the mechanical follow-through that closes the drift risk those fixes proved.
- **#986 / #988** — historical planned `frame/` splits. Overlap in intent with Finding 1 but not in concrete filing — this report provides the measured 6-cluster breakdown and the 9-site EH walker inventory that those tracking issues lack.
- **#1049 / #1352 / #1543** — filter engine split, frame build/rewrite extraction, screen Wave-5 split. All correctly not re-reported (Finding 3 negative confirms them as exemplary).
- **#1540 / #1541 / etc.** — screen sub-thresholds (#3315 count-min sketch), log-only alarm-threshold. `syn_rate.rs` (504 LOC) is already a clean isolated module — no further split needed. The alarm/sub-threshold logic could be its own module without touching hot path per prompt, but `syn_rate.rs` already IS that module. No re-file.
- **#1537 / #1552** — RPM / failover tests. Not in this batch's files.

---

## Verification performed

- [x] Read `screen/mod.rs` (1540 LOC) — counted 25+ hashmap fields, 373-line `check_packet_with_zone_id_opts`, 103-line `check_flowless_screens_opts`, 75-line `scan_sweep_drop_on_new_flow`, 63-line `validate_syn_cookie_ack_on_session_miss`
- [x] Read `screen/scan.rs` (1213 LOC) — measured 621 prod / 590 test, confirmed `ScanCore<T>` generic + `PortScanTracker`/`IpSweepTracker` thin wrappers, `per_zone_count` O(1), `least-suspicious` eviction, window-aware cleanup, 12 regression tests including fail-on-revert #4418/#4379
- [x] Read `screen/stateless.rs` (262), `screen/packet.rs` (174), `screen/rate.rs` (609), `screen/syn_rate.rs` (504), `screen/syncookie.rs` (600), `screen/extract.rs` (400) — all clean, `#[inline]` discipline
- [x] Read `afxdp/frame/inspect.rs` (1813) — counted 6× duplicated EH match arm (`0|43|60|135|139|140|253|254` + 51 AH + 44 Frag + 59 None + `_ => Some`), 6 responsibility clusters (EH walk, frag predicates, port pipeline, filter-match builders, ICMP suppress, session-flow parsers), measured largest fn `parse_session_flow_from_bytes` (140 LOC)
- [x] Coarsely measured largest fns in `screen/mod.rs`, `frame/inspect.rs`, `frame/mod.rs`, `policy.rs`, `filter/mod.rs` via Python (see analysis traces)
- [x] Read `afxdp/frame/mod.rs` (1710) — confirmed `build/` (6 files) + `rewrite/` (4 files) already extracted per #1352, remaining 1710 LOC is 5 clusters (NAT apply ~550, inject ~130, DSCP 38, csum verify 191, L2 rewrite ~300)
- [x] Read `afxdp/frame/wg.rs` (1561) — prod ~900 LOC + tests ~650 LOC in same file; `outer_physical_egress_ifindex` + tests for #2680/#2701/#3992/#2837
- [x] Counted LOC: `frame/` total 8290 prod / 19027 inc tests/prop, `screen/` 4890 prod / 10697 total, `policy.rs` 3598, `filter/` ~4000, `runtime.rs` 503
- [x] Read `policy.rs` (3598) — counted 4 responsibilities (zone-policy 2200 + appid 350 + counters 400 + app matching 600), verified AppCatalog zero coupling (no PolicyState import, pure 5-tuple map), verified counter coalescer = same pattern as filter's `PendingFilterCounterRecord`
- [x] Read `filter/mod.rs` (939) — confirmed 3-way split (compiler 1056 + engine ~2000 + policer 504), `FilterState` 15+ iface maps correctly maintained, no monolith
- [x] Read `afxdp/types/runtime.rs` (503) — confirmed pure relocation from types/mod.rs (#68.4), `WorkerContext` 16 fields (#945), no policy bypass
- [x] Checked prior reviews: `/tmp/ps-review-039-a1d.md` (session table — #4421 DUP + Arc clone perf), `/tmp/ps-review-038-A1_rust_dataplane_packet-b1/b2.md` (infra + screen/policy negative, GRE-inner byte-order F1, L-01 IHL<5, L-02 FlowRrRing, L-03 MTU>65535), `/tmp/ps-review-038-A2_rust_dataplane_nat-b1.md`, `/tmp/ps-review-038-final.md` — confirmed dedup (#4421, #4399, #4517, #2150, #4555, #4566, etc.)
- [x] Checked `docs/engineering-style.md` — modularity discipline: ~2000 soft / ~3000 hard file LOC, no god functions >100 lines / >8 params (with `poll_binding_process_descriptor` as cautionary example — #945 down from 31 to 15 params, still tracked as #961)
- [x] Verified hot-path preservation invariants: no new alloc on parse path (walker returns `Option<(usize,u8)>` / small enum), no new heap, `#[inline(always)]` preserves same codegen for EH walk, `CompiledApplications::matches` stays `#[inline]`, `record_policy_hit_counter` stays `#[inline(always)]` with thread-local
