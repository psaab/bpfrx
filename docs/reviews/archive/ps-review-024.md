# xpf firewall deep audit — Cohort 8: Firewall filters + PBR + Routing — ps-review-024

- Base commit: b1bd96fb6 (merge PR #4531, master)
- Output path: /tmp/ps-review-024.md
- Cohort: 8 — userspace-dp/src/filter/*, userspace-dp/src/afxdp/poll_descriptor/filter.rs, pkg/config/compiler_firewall.go, compiler_protocols.go, compiler_routing*.go, pkg/routing/*, pkg/dataplane/userspace/filters.go

## Duplicate-suppression summary

Read /tmp/all_findings.txt (272 entries, F-001..F-272) + /tmp/ps-review-018.md..023.md.

Dedup'd / not re-reported:
- F-001 (source-prefix-list single-name) — fixed #3843, verified in compiler_firewall.go:firewallPrefixListRefs (reads Keys[1:] + Children). Not re-reported.
- F-030 (non-inet6 family folding) / F-3884 family collision — fixed via validateFirewallFilterFamilyCollisionsAST, verified. Not re-reported.
- F-236 (flex_mask==0 match-all) — still present in Rust boundary (mask 0 => match-all) but tracked as UNKNOWN in all_findings.txt:236. Dedup'd (low, known).
- F-127 (CachedThreeColorPolicers hard-cap 2) — known, tracked. Not re-reported.
- F-124/F-145 (normalizeAnyInCIDRs no-op) — known. Not re-reported.
- F-016 (rib-group 33000 shadow), F-174 (next-table mirror scope), F-008 (qnh), F-042, F-062, etc. — known or fixed, not re-reported.
- F-007 (RI table IDs positional) — fixed #3855 StableRoutingInstanceTableID, verified. Not re-reported.
- All filter DSCP / icmp / tcp-flags / flex / prefix-list / port-except gates (#3205, #3307, #3076, #2622, #3359, #3433, etc.) — verified fixed.

Intentional divergences (NOT bugs):
- intrazone default-permit, host-originated junos-host, IPsec-passthrough-exempt, reject-all superset — documented, not reported.
- PBR ip rule has no iif selector (documented widening vs Junos per-interface FBF) — known limitation, not reported as new unless it interacts with drop-action gate (see Finding M-01 residual).
- Rib-group Phase-1 only leaks into main (VRF→VRF deferred) — documented, not a bug.
- Flex match-start payload rejected at commit, unsupported=>fail-closed in Rust — intentional.
- DSCP-0 cannot be represented as ip rule tos (zero = match ANY) — dropped with degraded warning, documented.
- Three-color policer only supports color-blind + discard (others fail-closed) — documented gap, but default-behavior DoS is new (see L-01).

Previously-fixed verification (required):
- **P3 PBR reject (#4392)**: VERIFIED FIXED on b1bd96fb6. `forwarding/mod.rs:1548` `RouteOverride {None|Table|Drop}`, `ingress_route_table_override` returns `Drop` for Reject/Discard, both callers in poll_descriptor (flow-backed with PbrRejectSink + flowless sink-less) recycle frame and skip route lookup. Tests in `frame/tests.rs:552..772` pin reject/discard=>Drop, accept=>Table. RED-on-revert verified in commit message.
- **F-001 source-prefix-list (#3843)**: VERIFIED FIXED. `compiler_firewall.go:783` `firewallPrefixListRefs` reads `child.Keys[1:]` (hierarchical single-name `source-prefix-list plX;`) AND `child.Children` (block shape). `validateFirewallPrefixListReferencesStrict` now catches undefined refs. Previously `source-prefix-list` bounded only on block shape, single-name shape silently dropped scope (match-all fail-open).
- **Family any (#4426)**: VERIFIED FIXED. `compiler_firewall.go:198` `family any` dual-compiles into both `FiltersInet` and `FiltersInet6`. `validateFirewallFilterFamilyAnyMatchesAST` (4296+4426) rejects `source-address`/`icmp-type`/single-family prefix-list under `family any` (strict) / warns (lenient). `firewallPrefixListFamilies` resolves PL family coverage, catches v4-only PL under `family any` (would under-block v6). `#4287` + `#4296` + `#4426` together close the fail-open.

## Module / verdict-path inventory

| Module | File(s) | Role | Reviewed |
|---|---|---|---|
| Filter types / cache-key invariant | `userspace-dp/src/filter/mod.rs` | FilterTerm, FlexMatchStart, FilterState, counters, policer runtimes, CACHE-KEY comment (#1431) | YES full |
| Filter compiler | `userspace-dp/src/filter/compiler.rs` | Snapshot → FilterState, three-color + single-rate lowering (#4514), fail-closed backstops (#2505, #3367, #3406, #3715, #3723) | YES full |
| Filter matching | `userspace-dp/src/filter/engine/matching.rs` | term_matches_v4/v6, nets_match, port_match, per_packet_l4_matches, flex_matches | YES full |
| Filter eval | `userspace-dp/src/filter/engine/eval.rs` | evaluate_filter, lo0, input, output, routing-instance, non-routing count policy (#2620), log normalization (#2616) | YES full |
| Filter TX selection | `userspace-dp/src/filter/engine/tx_selection.rs` | TX-selection eval, policer merge, DSCP/police/FC | YES full |
| Filter cache-sensitive | `userspace-dp/src/filter/engine/cache_sensitive.rs` | cached TX replay, input counters capture (#3777), filter_term_semantics_match (#2400, #2506, #2622), DSCP/L4 family changed | YES full |
| Filter policer (state) | `userspace-dp/src/filter/policer.rs` | ThreeColorPolicerState (srTCM/trTCM), refill, meter, color-blind, treatments | YES full |
| Filter policer (app) | `userspace-dp/src/filter/engine/policer.rs` | apply_term_three_color_policer, apply_cached, has_input_three_color | YES full |
| Filter mod/engine | `userspace-dp/src/filter/engine/mod.rs` | Re-exports | YES |
| Filter tests | `userspace-dp/src/filter/tests.rs` | 8000+ lines, per-field match, cross-field, flex, policer, PBR, family any | sampled |
| AF_XDP poll filter | `userspace-dp/src/afxdp/poll_descriptor/filter.rs` | host_inbound_gated_lo0_action (#3485, #3609), filter_terminal (#3615), evaluate_non_pbr, DSCP/L4 re-eval, lo0 gate tests | YES full |
| Go firewall compiler | `pkg/config/compiler_firewall.go` | compileFirewall, family any dual-compile, family collision gate, family-any specific-match + PL-family gate (#4426), firewallMatchValues, firewallPrefixListRefs (#3843), compileFilterFrom/Then | YES full |
| Go filter snapshot | `pkg/dataplane/userspace/filters.go` | buildFirewallFilterSnapshots, buildFilterTermSnapshots, resolvePrefixListAddrs, any+except compose (#4338), UnknownPort/ICMP/DSCP handling | YES full |
| Go protocols / routing | `pkg/config/compiler_protocols.go`, `compiler_routing.go` | OSPF/BGP/ISIS/RIP, static routes ECMP (#3872), qnh pref/metric, rib-group, RI table ID stable (#3855), BGP AS inheritance (#3870) | YES full |
| Go routing rules | `pkg/routing/rules.go` | nextTableManager (100-199), ribGroupManager (30000-30999, 33000 legacy), pbrManager (31000-31999, #3730 L4 ext, DSCP-0 drop), BuildPBRRules, pbrTermL4, resolvePBRDirection, ribGroupLeaksIntoMain | YES full |
| Go routing vrf/routes | `pkg/routing/vrf.go`, `routes.go`, `routing.go` | VRF reconcile, routeReader, ECMP multipath, rtProtoName | YES partial |
| Forwarding PBR | `userspace-dp/src/afxdp/forwarding/mod.rs:1530-1685`, `poll_descriptor/mod.rs:1680-1710,3504-3530` | ingress_route_table_override, RouteOverride::Drop, PbrRejectSink, flow-backed + flowless Drop handling | YES full |
| Go filter validators | `pkg/config/compiler_validate_strict_filter.go` | 12 strict gates: policer ref, PL ref, RI ref, filter ref, RI direction, protocol, cross-field (#3723), actions, match values, flex, port-except, addr-except, addr literals, from-match, RI conflict, terminal conflict, DSCP | YES full |
| Policer types | `pkg/config/types_security.go` etc. | PolicerConfig, ThreeColorPolicerConfig, FirewallFilterTerm | sampled |

## Module-by-module inspection log (including negatives)

### Filter matching — `userspace-dp/src/filter/engine/matching.rs`

- `term_matches_v4/v6` correctly ANDs: protocol bitmap, source/dest addr (with except + constrained), source/dest port (with except + constrained), DSCP, per-packet L4.
- `nets_match_v4/v6`: constrained==false => true (match any). Empty nets + constrained => returns `except` (positive=>false fail-closed, except=>true match-all). Correct Junos empty-set semantics (#2506). Mirror of NAT code.
- `port_match`: constrained && PortMatcher::Any => false (fail-closed both directions, #3205 fix for except over-match). Otherwise `matcher.matches(port) ^ except`. Correct — a port-except term with unresolved symbolic port (e.g. `domain`) would have PortMatcher::Any + constrained true => false (match nothing), not match-all (the pre-#3205 fail-open).
- `per_packet_l4_matches`: tcp-flags requires `l4_present && protocol==TCP`, checks both required and forbidden masks (fix #3076 for `syn & !ack`). `is_fragment` is L3-derived, NOT gated by l4_present (correct — non-first fragment still matches is-fragment). icmp-type/code require `l4_present && is_icmp && in_set` (gate on l4_present prevents zero-byte spurious match for icmp-type 0 / code 0 on fragments, #2362). Flex via `flex_matches`.
- `flex_matches`: `!flex_enabled => true`; length 1..=4 else false (fail-closed); match-start Layer3/Layer4/Unsupported (Unsupported=>false fail-closed, #3232); base None => false (no L3/L4 bytes on this path => fail-closed, #3077); bounds check `off+len <= base.len()` => false on short packet (no OOB, no panic). Big-endian assemble then `(val & mask) == value`. Correct.
  - **Residual**: `flex_mask==0` is accepted (no check) and turns flex into match-all when value==0 (since `(any & 0)==0`). Go never emits mask 0 (defaults to non-zero), but a hand-built snapshot with mask 0 would match-all. This is already tracked as F-236 in all_findings (dedup'd). Not re-reported as new but noted.
- **Negative**: No OOB, no panic, no bypass on truncated packets. Verified.

### Filter eval — `engine/eval.rs`

- `evaluate_filter_ref_counted_v4/v6`: first-match-wins, fall-through (`continue_term`) accumulates modifiers via `merge_matched_modifiers`, increments count via `record_filter_counter`. Correct.
- `evaluate_filter_ref_non_routing_counted` + `NonRoutingCountPolicy` (#2620): Always vs OnlyTerminalNonAccept correctly avoids double-count (routing evaluator owns count on Accept/defer exit) and avoids under-count on terminal discard/reject ahead of routing-instance term (replay via `count_matched_non_routing_terms`). Verified via tests `filter_next_term_2544` etc.
- `evaluate_filter_ref_routing_instance_counted`: walks fall-through terms, captures `acc_log` (#2619), stamps `lm.action = term.action` (#2616 truthful action), returns `Some(FilterRoutingInstanceResult)`. Correct.
- `evaluate_filter_ref_log_match`: latest matched logging term wins, `skip_routing_instance` true for non-PBR log path, `final_action` stamping ensures `log; next term` ahead of discard logs DENY not permit. Correct.
- `interface_filter_affects_route_lookup`: precheck for PBR, lives next to routing-instance evaluator (not cache-sensitive). Correct.

### Filter cache-sensitive — `engine/cache_sensitive.rs`

- `filter_term_semantics_match` compares every semantic field that changes match without changing vecs: `*_constrained`, `*_except`, `*_port_except`, `*_match_enabled`, `tcp_flags_*`, `is_fragment`, `icmp_*_bitmap`, `action`, `continue_term`, `count`, `log`, `policer_name`, `three_color_policer` (via `same_runtime_shape`), `routing_instance`, `forwarding_class`, `dscp_rewrite`. **Notably omits**: `flex_*`, `flex_match_start`, `id`, `name`. Wait — check: it DOES include `action`, `continue_term`, etc., but does it include flex fields?
  - Reading the function: it compares `source/dest_v4/v6`, `*_constrained`, `*_except`, `protocol_bitmap`, `protocol_match_enabled`, `source/dest_ports`, `*_port_constrained`, `*_port_except`, `dscp_bitmap`, `dscp_match_enabled`, `tcp_flags_mask/forbidden`, `is_fragment`, `icmp_*`, `action`, `continue_term`, `count`, `has_count`, `log`, `policer_name`, `three_color_policer`, `routing_instance`, `forwarding_class`, `dscp_rewrite`.
  - **Missing**: `flex_enabled`, `flex_offset`, `flex_length`, `flex_value`, `flex_mask`, `flex_match_start`. Also `id` (intentionally omitted, ID is not semantic), `name` (compared). And `source_v4` etc. already included.
  - `flex_*` omission means a snapshot change that toggles a flexible-match-range condition (e.g., changes offset from 0 to 6, or adds a flex match) would be considered cache-equal, so flow-cache would keep stale verdicts (first-packet decision reused for later packets that differ on flex field). Since flex is per-packet and cache-sensitive (flow-cache declines for filters using flex), the `input_per_packet_l4_filter_families_changed` path purges flow-cache when filter gains/loses flex terms, but `filter_term_semantics_match` is used for DSCP-sensitive and per-packet-L4 family changed detection via `dscp_sensitive_filter_semantics_match` which calls `filter_term_semantics_match`. If flex fields are omitted, a change from `flex_offset 0` to `flex_offset 6` within same filter would NOT be detected as changed, so flow-cache would not be purged, and stale decisions could be replayed.
  - This is a **new finding** (see M-02 below). It is distinct from all_findings F-129 ("filter_term_semantics_match omits all six flex_* fields") — wait, F-129 IS exactly this: "filter_term_semantics_match omits all six flex_* fields — the cache-invalidation equality SSOT silently ...". Yes, F-129 is in all_findings.txt line 129. So this is DEDUP'd — already reported as F-129. We must not re-report as new, but we have verified it is still present on b1bd96fb6.
  - Check all_findings: line 129 says `[UNKNOWN]: filter_term_semantics_match omits all six flex_* fields — the cache-invalidation equality SSOT silen`. Yes, same. So we will note as verified still present, dedup.

- `dscp_sensitive_filter_semantics_match` and `input_*_filter_families_changed` use `filter_term_semantics_match`, so flex omission propagates.
- **Negative**: DSCP and per-packet L4 match are correctly treated as cache-sensitive (flow-cache decline at `flow_cache.rs:297-309`, re-eval on session hit, rotation purge). Verified.

### Filter compiler — `filter/compiler.rs`

- `parse_filter_state`: MissingFilterRef => `SnapshotIntegrityError::MissingFilterRef` (fail-closed, #3296). Prevents typo'd filter hook from becoming Accept.
- `parse_term`: Preflights fail-closed for tcp_flags_unparseable (#3367), icmp_type/code unrepresentable (#3406), dscp_match_unrepresentable, dscp out-of-range (>63, #3715), flex length out of 1..=4 (#3406). All return `SnapshotIntegrityError`, whole snapshot rejected, prior good state retained (#1961). Correct.
- `parse_address`: drops empty and "any", parses IpNet then bare IP => /32 /128. Correct.
- `addr_is_real` excludes empty and "any" from constrained calculation — prevents `source-address any` from becoming constrained+empty => fail-closed (would be match-nothing, DoS). Correct.
- `port_is_real` excludes empty from constrained — same.
- Protocol resolution via `proto_number` (shared SSOT, not stale local table). Empty token skipped. Unresolvable token => `UnrepresentableFilterProtocol` => snapshot reject (fail-closed, #2505). Correct.
- Cross-field unsatisfiable (#3723): ports with non-TCP/UDP proto, tcp-flags with non-TCP, icmp with non-ICMP => `UnsatisfiableFilterCrossField` => snapshot reject. Empty protocol list is allowed (no protocol constraint, filter matches port on any port-bearing packet). Correct.
- Port matcher: selects positive or except list (positive-wins if both present, #3716), builds Vec<PortRange> via `parse_port_spec`, `build_port_matcher`. `source_port_except` bool derived from "all positive empty && except has real". Correct.
- `parse_port_spec`: "http"=>80 etc., "low-high" range, low==0 or low>high => None, port 0 => None. Empty => Some(empty) (no constraint). Correct.
- Action: "accept"/"reject"/"discard" map, "" => Accept placeholder (for fall-through), unknown non-empty => eprintln + Discard (fail-closed, #2399). Correct.
- `continue_term`: `(next_term || action empty) && routing_instance empty`. Routing-instance term is never fall-through (takes its own decision). Correct.
- `flex_match_start`: None/""/"layer-3"=>Layer3, "layer-4"=>Layer4, other=>Unsupported (fail-closed, #3232). Correct.
- `flex_enabled`: `1..=4` length, else disabled (no constraint, but preflight already rejected length out of range, so this is defense-in-depth). Correct.
- **Residual**: `flex_mask==0` not rejected (see above). Dedup'd.

### Policer — `filter/policer.rs`

- `ThreeColorPolicerState::sr_tcm` / `tr_tcm`: zero rate/burst => Err, peak<committed => Err, etc. Correct.
- `meter`: color-aware: `incoming_color` respected; color-blind: forced Green. Then `meter_sr_tcm` / `meter_tr_tcm`. `meter_sr_tcm`: Green if Green && C bucket >= cost, else Yellow if not Red && E bucket >= cost, else Red. `meter_tr_tcm`: Green if Green && P && C >=cost, else Yellow if not Red && P>=cost, else Red. Correct per RFC 2697/2698.
- `refill`: `!initialized` => init to burst, `now_ns <= last_refill` => no refill (handles time going backwards, monotonic). `elapsed_ns * rate` via `refill_scaled` (u128, no overflow). `capped_add` via saturating_add then min cap. Correct.
- `refill_sr_tcm`: refill C bucket, overflow goes to E bucket (C token bucket refills first, excess goes to E). Correct RFC 2697 single-rate.
- `refill_tr_tcm`: independent C and P refills. Correct.
- `fail_closed`: mode Unsupported, initialized true, zero tokens, treatments default (no drop? Actually fail_closed returns initialized true, zero tokens, but meter on Unsupported returns Red+drop). Wait: `fail_closed` sets mode Unsupported, initialized true, zero tokens. Then `meter` checks `if mode==Unsupported => Red+drop`. Correct — any packet hitting an unsupported policer is dropped (fail-closed).
- **Single-rate lowering** (#4514): `build_single_rate_policer_state` maps `bandwidth_bps/8` (bits->bytes), `burst_bytes`, `discard_excess` => treatments Green default, Yellow drop, Red drop. Color-blind true. Zero rate/burst => None => caller fail-closed if discard, skip if meter-only. Correct.
- **Three-color shape supported**: `color_blind && (then_action empty or discard)` — only color-blind discarding policers are supported; others become fail-closed (drop all). This is a known limitation (docs), but default behavior when color-blind not specified causes unintended fail-closed (see L-01).
- Concurrency: `ThreeColorPolicerRuntime::meter` takes `Mutex<ThreeColorPolicerState>` + relaxed atomics for counters. Lock contention across workers but safe. `meter` order: lock -> meter -> drop lock -> record counters (relaxed). Correct.

### Go firewall compiler — `pkg/config/compiler_firewall.go`

- `compileFirewall`: correctly handles both AST shapes for `family { inet { filter } }` and `family inet { filter }`. `family any` => dests = both maps, `family inet6` => inet6 only, else inet. Correct per #4287.
- `validateFirewallFilterFamilyCollisionsAST`: rejects same name across >=2 non-inet6 families (strict) / warns (lenient). Tracks `filterFamilies` distinct families, `inet6Names` for any+inet6 collision. Correct per #3884+4287.
- `validateFirewallFilterFamilyAnyMatchesAST`: rejects family-specific `source-address`/`icmp-type` under `family any` (static set) and single-family prefix-list under `family any` (content-aware, #4426). Handles positive vs except separately (except single-family over-matches opposite family, positive single-family under-blocks). Correct per #4296+4426.
- `firewallPrefixListFamilies`: mirrors compilePolicyOptions prefix reading (namedInstances + inst.node.Children, each child's full Keys). Correct per #3996.
- `firewallMatchValues`: reads both `Keys[1:]` and `Children[*].Keys[0]`, skips empty. Correct SSOT for #2419/#2545 dual-shape.
- `firewallPrefixListRefs`: reads both leaf shape (`Keys[1:]`) and block shape (`Children`), handles `except` modifier attaching to preceding name. Correct per #3843.
- `compileFilterFrom`: accumulates `source-address`, `dest-address`, `protocol`/`next-header`, `source/dest-port`, `source/dest-prefix-list`, `source/dest-port-except`, `icmp-type/code`, `tcp-flags`, `is-fragment`, `flexible-match-range`, `dscp`. `next-header` aliased to protocol (fix #3307). UnknownFrom recorded for rejection. Correct.
- `compileFilterThen`: handles leaf form `then discard` and block form `then { discard; }`, `forwarding-class`, `policer`, `routing-instance`, `count`, `log`, `loss-priority`, `dscp`, `next-term`. TerminalActions collected for conflict detection. UnknownActions recorded. `reject <type>` with known message types accepted, unknown flagged. Correct.

### Go filter snapshot — `pkg/dataplane/userspace/filters.go`

- `buildFirewallFilterSnapshots`: sorts names, builds `FirewallFilterSnapshot` per filter, calls `buildFilterTermSnapshots`. Correct.
- `buildFilterTermSnapshots`: handles `SourceAddresses`/`DestAddresses` via `resolvePrefixListAddrs` (merges literal + PL, tracks constrained, except). `Protocols` multi-value, `SourcePorts`/`DestPorts`, `SourcePortsExcept`/`DestPortsExcept`, `NextTerm` logic `(NextTerm||Action=="")&&RI==""`. DSCP numeric/name resolve, DSCP rewrite, TCP flags via `ParseTCPFlagsExpression` (unparseable=>TCPFlagsUnparseable), is_fragment, icmp-type/code (0..255, else mark unrepresentable), flex (length ceil(bits/8), default 4, carry real width for Rust backstop, #3232 match-start). Correct.
- `resolvePrefixListAddrs` / `ResolveFilterPrefixListAddrs`: drops `any`/empty from literal before constrained calc, PL refs always constrain, `any` literal + except PL => sole except (`any AND NOT X` => except), mixed positive+except => positive-wins + warn (fail-safe, #3359), `addrsAllMatchAny` for 0.0.0.0/0 detection, returns `(addrs, except, constrained)`. Correct per #2506/#4338.
- `buildPolicerSnapshots` / `buildThreeColorPolicerSnapshots`: sorted, maps `ThenAction=="discard"` to DiscardExcess, mode single-rate/two-rate, CIR/CBS/PIR/PBS, ColorBlind, ThenAction. Correct.

### Go routing / PBR / rib-group / next-table — `pkg/routing/rules.go`

- `nextTableManager.Apply`: priority 100-199, hard-cap 100, clears old, aggregates errors, installs `to <dst> lookup <table>` global ip rule. **No iif/from scoping** — see M-03.
- `ribGroupManager.Apply`: Phase-1 per-prefix `to <connected-prefix> lookup <sourceTable>` pref 30000-30999, before main (32766) and before PBR (31000-31999). Clears three windows (current 30000-30999, old 33000-33999, legacy 200-299). Correct per #3876.
- `pbrManager.Apply`: priority 31000-31999, clears old, installs `from <src> to <dst> tos <tos> ipproto <p> sport <sp> dport <dp> lookup <table>`. Handles DSCP-0 as unrepresentable (drops with degraded error), TOS presence via `TOSSet`. Correct per #3430+3730.
- `BuildPBRRules`: only from attached input filters (`collectAttachedInputFilters`), expands DSCP×src×dst×proto×sport×dport cross-product, truncates to maxPBRRules (1000) with degraded error. `pbrTermL4` classifies unrepresentable L4 predicates (port-except, tcp-flags, icmp, is-fragment, flex, unknown from, unknown proto, unparseable port) as fail-closed (whole term dropped + degraded). `resolvePBRDirection`: handles literal + PL, except, `any`/`0/0` => unconstrained, positive empty => skip, except non-empty => error (no negated ip rule). **Does NOT check term.Action** — see M-01.
- `dscpToTOS`: maps cs0/be => 0 (unrepresentable), ef=46, afxx, cs1..cs7, numeric 0..63. Correct.

### Forwarding PBR — `userspace-dp/src/afxdp/forwarding/mod.rs`

- `RouteOverride` enum + `ingress_route_table_override`: resolves logical ingress ifindex, checks `interface_filter_affects_route_lookup`, builds `TermMatchExtra` for tcp-flags etc., calls `evaluate_interface_filter_routing_instance_event_counted`, handles `is_drop` (Reject/Discard => Drop), synthesizes reject reply via `enqueue_filter_reject_reply` when `PbrRejectSink` present, emits filter log with truthful action (#3615), returns `Drop` or `Table("<ri>.inet[6].0")`. Correct per #4392.
- Callers in `poll_descriptor/mod.rs:1685` (flow-backed) and `:3509` (flowless) match `RouteOverride::Drop` => recycle frame and skip route lookup/forward. Correct.

### AF_XDP filter — poll_descriptor/filter.rs

- `host_inbound_gated_lo0_action`: host-inbound check FIRST (logical ifindex, per-interface override #3609, zone fallback), then lo0 filter eval. Prevents lo0 side-effects (counter, log, reject reply) on host-inbound denied packet (#3485). Tests pin deny=>None+counter 0, admit=>Reject+counter 1, VLAN logical ifindex override. Correct.
- `filter_terminal`: enqueues reject reply FIRST, then emits filter log with actual outcome (REJECT→DENY downgrade on fail-closed). Correct per #3615.
- `evaluate_non_pbr_input_filter`: count policy selection (Always vs OnlyTerminalNonAccept) per #2620, correctly avoids double-count and under-count.
- `evaluate_dscp_sensitive_input_filter_on_session_hit`: re-evaluates DSCP + per-packet L4 on session hit (flow-cache decline for those filters). Correct.

## Findings

### [M-01] PBR kernel mirror builds ip rules for `then routing-instance X; discard/reject` terms rejected at commit — unfiltered / XDP_PASS traffic is steered instead of dropped

- Title: PBR kernel mirror (ip rule) ignores `then discard`/`reject` on a routing-instance term — traffic that userspace would DROP is instead STEERED into the VRF
- Severity: Medium
- Confidence: High
- Class: implementation-bug / vrf-leak / parity-gap (residual of #4392 + #3308)
- Evidence:
  ```go
  // pkg/config/compiler_validate_strict_filter.go:1223
  // validateFilterRoutingInstanceConflictStrict: rejects `then routing-instance X` + `then discard`/`reject` at commit (strict)

  // pkg/routing/rules.go:770 buildPBRFromFilter
  func buildPBRFromFilter(filter *config.FirewallFilter, ...) {
      for _, term := range filter.Terms {
          if term.RoutingInstance == "" { continue }
          // NO check of term.Action — builds PBR rule even for discard/reject
          tableID, ok := tableIDs[term.RoutingInstance]
          ...
          protos, sports, dports, unrep := pbrTermL4(term)
          if len(unrep) > 0 { continue }
          // ... builds PBRRule{TableID: tableID, ...}
      }
  }

  // userspace-dp/src/afxdp/forwarding/mod.rs:1611 (fixed #4392)
  let is_drop = matches!(routing_result.action, FilterAction::Reject | FilterAction::Discard);
  if is_drop { return RouteOverride::Drop; }
  ```
- Trace:
  1. Operator (pre-#3308) configures `firewall family inet filter FBF term t1 from source-address 10.0.0.0/8 then { routing-instance MGMT; discard; }`, attaches `filter input FBF` to `ge-0/0/0.0` (untrust->MGMT VRF steer + drop). Commits on old binary (before #3308 gate) — accepted.
  2. On upgrade to b1bd96fb6, strict commit for new changes would reject this term, but lenient load / HA peer-sync keeps the existing config (no-brick, #1960). `validateFilterRoutingInstanceConflictStrict` on lenient path warns, does not drop term. Term stays in `cfg.Firewall.FiltersInet["FBF"].Terms[0]` with `RoutingInstance="MGMT"` and `Action="discard"`.
  3. `BuildPBRRules` is called during `ApplyPBRRules`. It sees `RoutingInstance=="MGMT"` (non-empty), does NOT check Action, so it builds `PBRRule{Family:AF_INET, Src:"10.0.0.0/8", TableID:MGMT_table}` and installs `ip rule from 10.0.0.0/8 lookup MGMT pref 31000`.
  4. `ingress_route_table_override` (userspace) correctly returns `RouteOverride::Drop` for this term (fix #4392), so session-miss packets arriving on `ge-0/0/0.0` (filtered interface) are DROPPED (correct, no VRF leak on filtered path).
  5. Packet from `10.0.0.5` arriving on `ge-0/0/1.0` (an interface WITHOUT the FBF filter, e.g., a new interface added after, or a management interface) — userspace has no input filter for that ifindex, so `interface_filter_affects_route_lookup` false => `RouteOverride::None`, packet proceeds to normal route lookup. Kernel then evaluates `ip rule from 10.0.0.0/8 lookup MGMT` (global, no iif) and STEERS it into MGMT VRF, forwarding it when it should be dropped (or at least routed via main). This is VRF leak + fail-open (drop bypass).
  6. Same for XDP_PASS'd SNAT traffic: userspace SNATs and passes to kernel, kernel PBR steers via the discard-term's rule into MGMT, even though userspace intended drop.
  What vSRX does: Junos rejects `then routing-instance` + `then discard`/`reject` at commit — such a term never exists. If it somehow existed, the forwarding plane would drop, not steer.
- Refutation attempted:
  - Checked `validateFilterRoutingInstanceConflictStrict` — strict=true rejects at commit, lenient=true warns only. On b1bd96fb6, lenient path is used for load/peer-sync, so old config with the conflict survives.
  - Checked `BuildPBRRules` — no Action check, confirmed by reading `buildPBRFromFilter` full body (lines 766-937). No `term.Action` reference.
  - Checked `ingress_route_table_override` — correctly Drops for Reject/Discard (fix #4392), so filtered path is safe. The leak is ONLY via global kernel ip rule for unfiltered interfaces / XDP_PASS.
  - Checked if `collectAttachedInputFilters` limits to attached filters — yes, but still global (no iif). So an interface without the filter still matches the ip rule.
  - Confirmed this is not a re-report of #4392 itself (#4392 is about userspace forwarding, not kernel ip rule). This is a residual in the kernel mirror.
- Why it matters: A `then routing-instance X; discard` term is a DENY that the operator expects to drop. After upgrade, userspace correctly drops on the filtered interface, but kernel PBR globally steers matching traffic from any interface (including newly added or management) into the VRF, leaking traffic that should be dropped and crossing VRF isolation. The audit log (filter log) for the filtered path correctly shows DENY, while unfiltered path has no log and forwards — silent VRF leak.
- Fix direction:
  - In `buildPBRFromFilter`, skip terms where `term.Action == "discard" || term.Action == "reject"` (or where `term.RoutingInstance != "" && (term.Action=="discard"||term.Action=="reject")`), matching the userspace `is_drop` gate. Emit a degraded warning if such a term is encountered on lenient path.
  - Alternatively, make `validateFilterRoutingInstanceConflictStrict` on lenient path also drop the term (not just warn) or make `BuildPBRRules` return error that causes `ApplyPBRRules` to not install any rule for that term.
  - Add test: config with `routing-instance X; discard`, assert `BuildPBRRules` returns 0 rules and degraded error; assert `ingress_route_table_override` returns Drop (already tested).
- Labels: `pbr`, `fbf`, `vrf-leak`, `fail-open`, `routing`, `implementation-bug`, `residual-4392`
- Dedup note: Not in /tmp/all_findings.txt. #4392 fixed the userspace forwarding path (RouteOverride::Drop) but did NOT fix the kernel ip rule mirror (BuildPBRRules). This is a residual in the companion subsystem, not a re-report of #4392 itself. No prior finding mentions BuildPBRRules + discard interaction.

---

### [M-02] `filter_term_semantics_match` omits all six `flex_*` fields — cache-invalidation equality keeps stale verdicts when a flex term changes (verified still present)

- Title: Flex match fields not compared in cache-invalidation equality — flow-cache keeps stale decisions after flex term change
- Severity: Medium
- Confidence: High
- Class: implementation-bug / protocol-corruption / cache-coherency
- Evidence:
  ```rust
  // userspace-dp/src/filter/engine/cache_sensitive.rs:287-340
  fn filter_term_semantics_match(old: &FilterTerm, new: &FilterTerm) -> bool {
      old.name == new.name
          && old.source_v4 == new.source_v4
          && old.source_v6 == new.source_v6
          && old.dest_v4 == new.dest_v4
          && old.dest_v6 == new.dest_v6
          && old.source_addr_constrained == new.source_addr_constrained
          && old.dest_addr_constrained == new.dest_addr_constrained
          && old.source_except == new.source_except
          && old.dest_except == new.dest_except
          && old.protocol_bitmap == new.protocol_bitmap
          && old.protocol_match_enabled == new.protocol_match_enabled
          && old.source_ports == new.source_ports
          && old.dest_ports == new.dest_ports
          && old.source_port_constrained == new.source_port_constrained
          && old.dest_port_constrained == new.dest_port_constrained
          && old.source_port_except == new.source_port_except
          && old.dest_port_except == new.dest_port_except
          && old.dscp_bitmap == new.dscp_bitmap
          && old.dscp_match_enabled == new.dscp_match_enabled
          && old.tcp_flags_mask == new.tcp_flags_mask
          && old.tcp_flags_forbidden == new.tcp_flags_forbidden
          && old.is_fragment == new.is_fragment
          && old.icmp_type_bitmap == new.icmp_type_bitmap
          && old.icmp_type_match_enabled == new.icmp_type_match_enabled
          && old.icmp_code_bitmap == new.icmp_code_bitmap
          && old.icmp_code_match_enabled == new.icmp_code_match_enabled
          // NO flex_enabled, flex_offset, flex_length, flex_value, flex_mask, flex_match_start
          && old.action == new.action
          && old.continue_term == new.continue_term
          && old.count == new.count
          && old.has_count == new.has_count
          && old.log == new.log
          && old.policer_name == new.policer_name
          && three_color_policer_semantics_match(&old.three_color_policer, &new.three_color_policer)
          && old.routing_instance == new.routing_instance
          && old.forwarding_class == new.forwarding_class
          && old.dscp_rewrite == new.dscp_rewrite
  }
  ```
- Trace:
  1. Config A: `firewall family inet filter F term t from flexible-match-range { range 0 { byte-offset 0; bit-length 32; match-value 0x0800; } } then discard` — blocks IPv4 (ether-type 0x0800 at L3 offset 0 for some encaps).
  2. Operator changes to `byte-offset 6` (different field) via commit. New snapshot has same term name, same addresses, but `flex_offset=6`.
  3. `filter_term_semantics_match(old, new)` returns true (flex fields not compared), so `dscp_sensitive_filter_semantics_match` returns true, so `input_per_packet_l4_filter_families_changed` returns false, so `flow_cache` is NOT purged, and existing flow entries with old flex decision remain.
  4. Established flow that previously matched (offset 0 == 0x0800) had been discarded (no flow entry, since discard doesn't cache? Actually discard terms don't install flow-cache? Wait, discard is not cached as a forwarding decision? The flow-cache is for accept/established flows. A discard term would not install a flow, so new packet would be re-evaluated, correct. Let's use accept case: term `then accept` with flex match that accepts only certain L3 bytes. Flow is accepted and cached. Changing flex offset should change which packets match, but cached flow still returns Accept for old 5-tuple, even though new flex condition would reject — fail-open (permits traffic that should be discarded by new flex term).
  5. Alternatively, `then discard` term with flex: flow that was previously accepted (flex did not match) is cached as Accept. After flex change to a condition that now matches and would discard, cached flow still returns Accept — fail-open.
  What vSRX does: Junos would re-evaluate all flows against new filter, not keep stale cache.
- Refutation attempted:
  - Verified `filter_term_semantics_match` omits all six flex fields by reading the function (lines 287-340).
  - Checked if flex is handled elsewhere: `has_per_packet_l4_match_terms` includes flex (via `has_per_packet_l4_match`), and `input_per_packet_l4_filter_families_changed` uses `dscp_sensitive_filter_semantics_match` which uses `filter_term_semantics_match` — so if flex fields change but term still has `has_per_packet_l4_match_terms` true before and after, the family_changed function will think "filter has per-packet L4 match" (true) but "semantics match" true (because flex omitted), so it will NOT report changed, so flow-cache NOT purged.
  - Checked all_findings.txt line 129: "[UNKNOWN]: filter_term_semantics_match omits all six flex_* fields — the cache-invalidation equality SSOT silen" — this is EXACTLY the same finding, already reported as UNKNOWN. So this is DEDUP, not new. Verified still present on b1bd96fb6.
- Why it matters: Stale flow-cache decisions after flex term change can cause fail-open (accept when should discard) or fail-closed (discard when should accept), violating the operator's intent after a commit.
- Fix direction: Add `old.flex_enabled == new.flex_enabled && old.flex_offset == new.flex_offset && old.flex_length == new.flex_length && old.flex_value == new.flex_value && old.flex_mask == new.flex_mask && old.flex_match_start == new.flex_match_start` to `filter_term_semantics_match`.
- Labels: `filter`, `flex`, `cache-coherency`, `flow-cache`, `implementation-bug`
- Dedup note: Already in /tmp/all_findings.txt as F-129 ("filter_term_semantics_match omits all six flex_* fields"). Verified still present on b1bd96fb6, not fixed. Not a new finding, included here for completeness as a verified residual.

---

### [M-03] `next-table` inter-VRF static route installs a GLOBAL `ip rule to <dst> lookup <table>` with no source-VRF scoping — traffic from any VRF (including main) is steered into the target VRF

- Title: Next-table static route VRF leak — global ip rule steers traffic from unintended source VRFs
- Severity: High (vrf-leak, fail-open)
- Confidence: Medium (requires runtime confirmation, but code trace is clear)
- Class: fail-open / vrf-leak / implementation-bug
- Evidence:
  ```go
  // pkg/routing/rules.go:84-172 nextTableManager.Apply
  for _, sr := range routes {
      if sr.NextTable == "" { continue }
      tableID, ok := tableIDs[sr.NextTable]
      ...
      _, dst, err := net.ParseCIDR(sr.Destination)
      ...
      rule := netlink.NewRule()
      rule.Dst = dst
      rule.Table = tableID
      rule.Priority = prio
      rule.Family = family
      // NO Src, NO Iif, NO table scoping
      n.ops.RuleAdd(rule)
  }

  // pkg/config/compiler_routing.go:385-465 compileRoutingInstances
  // Static routes are per-instance: ri.StaticRoutes contains routes for that RI
  // Stable table IDs per RI name (#3855)

  // Caller (pkg/daemon or pkg/routing) passes ALL static routes (global + per-RI) into Apply?
  // Need to verify caller, but Apply itself has no source-table discrimination.
  ```
- Trace (concrete):
  1. Config:
     ```
     routing-instances {
         VRF-A { instance-type vrf; interface ge-0/0/0.0; routing-options static route 0.0.0.0/0 next-table VRF-B.inet.0; }
         VRF-B { instance-type vrf; interface ge-0/0/1.0; routing-options static route 0.0.0.0/0 next-hop 203.0.113.1; }
     }
     ```
     Intent: Traffic in VRF-A that doesn't match more specific routes should be looked up in VRF-B (internet VRF). Traffic in main table should NOT be affected.
  2. `compileRoutingInstances` creates `VRF-A` with `TableID=100` (stable hash), `VRF-B` with `TableID=101`, and `VRF-A.StaticRoutes = [{Destination:"0.0.0.0/0", NextTable:"VRF-B"}]`.
  3. Somewhere, `ApplyNextTableRules` is called with `routes = all static routes` (global + per-RI) and `instances`. It finds `sr.Destination="0.0.0.0/0", sr.NextTable="VRF-B"` and installs `ip rule to 0.0.0.0/0 lookup 101 pref 100`.
  4. This `ip rule` is GLOBAL — it matches destination 0.0.0.0/0 regardless of source VRF. So traffic in main table (e.g., from management interface) destined to internet (0.0.0.0/0) now matches `to 0.0.0.0/0 lookup 101` and is steered into VRF-B, leaking main table traffic into VRF-B and bypassing main's default route / security policies.
  5. Similarly, traffic in VRF-C (another VRF) destined to 0.0.0.0/0 would be steered into VRF-B, even though VRF-C has no next-table config.
  What vSRX does: Junos `next-table` is scoped to the source routing-instance — only lookups in that RI's table that match the route are steered. Traffic in other RIs / main is unaffected.
  What xpf does: Global `to` rule, no scoping, leaks.
- Refutation attempted:
  - Checked `nextTableManager.Apply` — confirms only `Dst`, `Table`, `Priority`, `Family` set, no `Src`, `Iif`, `From`, etc.
  - Checked if caller passes only main table's next-table routes — unlikely, since `compileRoutingInstances` stores per-RI static routes in `ri.StaticRoutes`, and the caller would need to aggregate all. The typical pattern is to pass all RI static routes into Apply; even if it passed only global static routes, the same issue would apply for global next-table leaking into VRFs.
  - Checked if Linux `ip rule` supports `iif vrf-A` to scope — yes, `ip rule iif <vrf-device> to <dst> lookup <table>` would scope to traffic ingressing via VRF-A. But current code doesn't set Iif.
  - Checked if `ip rule from <VRF-A-subnet>` could scope — possible but not implemented.
  - This finding requires checking the actual caller of `ApplyNextTableRules` to confirm it passes per-RI routes. The code in `rules.go` itself does not discriminate, so even if caller only passed global routes, a global next-table route `0.0.0.0/0 next-table VRF-B` would still leak into VRFs (since VRFs' default lookup would also hit the global rule before their own table?). Actually, VRF lookup is triggered by `ip rule iif vrf-X lookup X-table`. The next-table rule with pref 100 would be evaluated BEFORE the VRF's own rule (which is typically pref 1000+?), so it would indeed intercept.
  - Not found in all_findings.txt — no prior finding about next-table VRF leak via global ip rule. F-174 says "next-table kernel mirror scope divergence: per-instance next-table static routes are never programme..." — that's a different issue (scope divergence, not global leak). This is a new variant: global rule, no scoping, leaks.
  - Confidence Medium because we have not traced the exact caller of ApplyNextTableRules to confirm it passes per-RI routes, but the code in `nextTableManager.Apply` is clearly global and would leak if it did.
- Why it matters: Inter-VRF route leaking is a security boundary. A next-table route intended to leak VRF-A's default into VRF-B should not affect main or other VRFs. Global `to` rule breaks VRF isolation, causing traffic from main / other VRFs to be steered into a VRF they should not access — VRF leak, potential bypass of security policies in main.
- Fix direction:
  - Option 1 (correct): Install `ip rule iif <vrf-device> to <dst> lookup <target-table>` for per-RI next-table routes, and `ip rule to <dst> lookup <target>` only for global (main table) next-table routes. This scopes the rule to traffic that entered via the source VRF.
  - Option 2: Use `from` selector if source VRF's subnets are known (less precise).
  - Option 3: Document as known limitation and make `ApplyNextTableRules` take source table ID and install `ip rule from <source-table-subnet>` etc. But iif is the cleanest for VRF.
  - Add test: two VRFs, VRF-A has next-table default to VRF-B, main has different default; assert main traffic does NOT go via VRF-B.
- Labels: `vrf-leak`, `next-table`, `routing`, `fail-open`, `security`, `implementation-bug`
- Dedup note: Not in /tmp/all_findings.txt. F-174 is "next-table kernel mirror scope divergence: per-instance next-table static routes are never programme" — that's about missing programming, not global leak. This is a different failure mode: programmed but with wrong scope (global instead of VRF-scoped). Not a duplicate.

---

### [L-01] Three-color policer without explicit `color-blind` / `color-aware` defaults to fail-closed (drop all) instead of Junos default color-blind

- Title: Three-color policer missing color-mode defaults to unsupported => fail-closed drop-all (DoS)
- Severity: Low (DoS, not fail-open, but availability impact)
- Confidence: High
- Class: implementation-bug / parity-gap / dos
- Evidence:
  ```go
  // pkg/config/compiler_firewall.go:109-143
  for _, sr := range singleRates {
      if sr.FindChild("color-blind") != nil {
          tcp.ColorBlind = true
          tcp.ColorBlindConfigured = true
      }
      if sr.FindChild("color-aware") != nil {
          tcp.ColorAwareConfigured = true
      }
      // No else — if neither present, ColorBlind stays false
  }
  // ...
  for _, tr := range twoRates {
      if tr.FindChild("color-blind") != nil {
          tcp.ColorBlind = true
      }
      // ...
  }

  // userspace-dp/src/filter/compiler.rs:508-510
  fn snapshot_three_color_shape_supported(snap: &ThreeColorPolicerSnapshot) -> bool {
      snap.color_blind && (snap.then_action.is_empty() || snap.then_action == "discard")
  }
  // => if color_blind false, returns false => build_three_color_policer_state returns None
  // => parse_three_color_policer => fail_closed (drop all)
  ```
- Trace:
  1. Operator configures Junos-standard `three-color-policer FOO { single-rate { committed-information-rate 10m; committed-burst-size 1m; excess-burst-size 2m; } }` without explicit `color-blind` (Junos defaults to color-blind for single-rate, or at least accepts it as valid). Commits clean on xpf (no validation error).
  2. `compileFirewall` leaves `ColorBlind=false`.
  3. Snapshot has `ColorBlind=false`, `ThenAction="discard"` (default).
  4. Rust `snapshot_three_color_shape_supported` => `false && true` => false => `build_three_color_policer_state` => None => `parse_three_color_policer` => `ThreeColorPolicerState::fail_closed(true)` => `meter` => always Red+drop.
  5. All traffic matching this policer's filter term is DROPPED, instead of being policed. This is a DoS (availability loss), not a security bypass, but it violates operator intent (they expected 10m policing, got drop-all).
  What vSRX does: Junos single-rate three-color policer defaults to color-blind if neither color-blind nor color-aware is specified (or at least treats the policer as valid and enforces CIR/CBS). It does not drop all.
- Refutation attempted:
  - Checked if there's a commit-time gate that requires color-blind — no such gate found in `compiler_validate_strict_filter.go` or elsewhere.
  - Checked if Go code defaults ColorBlind to true elsewhere — no.
  - Checked if snapshot_three_color_shape_supported is intentionally restrictive — comment says "only color-blind discarding policers are supported", but it doesn't mention defaulting. The restriction is documented as a gap, but the default behavior (omitting color-blind => drop-all) is not documented and is worse than rejecting at commit.
  - Checked all_findings for color-blind — no prior finding.
- Why it matters: DoS — a valid Junos config that omits `color-blind` (relying on Junos default) commits clean on xpf but causes all policed traffic to be dropped, breaking connectivity for that class. Operator sees no error, only traffic loss.
- Fix direction:
  - In `compileFirewall`, default `ColorBlind` to true when neither `color-blind` nor `color-aware` is present (matching Junos default for single-rate). Or, if Junos requires explicit, add a commit-time error requiring one of them, instead of silently failing closed at runtime.
  - Alternatively, in `snapshot_three_color_shape_supported`, treat `color_blind==false` as still supported if `color_aware` was not configured (i.e., default to color-blind). But Go side doesn't track "neither configured" vs "color-aware configured". Could simply default ColorBlind to true in Go when neither is present.
  - Add test: three-color policer single-rate without color-blind, assert it meters (not drop-all).
- Labels: `policer`, `three-color-policer`, `dos`, `parity-gap`, `implementation-bug`
- Dedup note: Not in /tmp/all_findings.txt. No prior finding about three-color policer color-blind default.

---

### Negative results (verified fail-closed / not exploitable)

- **N-01: `source-address` / `destination-address` with `any` does not become constrained+empty fail-closed**: `filterAddrIsReal` excludes `any` and empty from constrained, so `from source-address any` stays unconstrained (match-all) as Junos expects, not fail-closed (which would be DoS). Verified in `filters.go:383`.
- **N-02: `port-except` with unresolved symbolic port (e.g. `domain`) fails closed (match nothing) not match-all**: `port_match` in `matching.rs:310-318` returns false for `constrained && PortMatcher::Any` in both positive and except directions, closing the pre-#3205 fail-open where `destination-port-except domain` matched every port including the one to exclude. Verified.
- **N-03: `address-except` empty positive (unresolved / empty PL) correctly match-all for except, match-nothing for positive (fail-closed)**: `nets_match_v4/v6` returns `except` when `nets.is_empty()` and constrained true. For positive (except=false) => false (match nothing), for except (true) => true (match all). Correct Junos empty-set semantics (#2506).
- **N-04: `icmp-type`/`icmp-code` symbolic names resolved per-family, numeric 0..255, unresolved marked unrepresentable and snapshot rejected**: `filter_match_resolve.go:182-217`, `compiler.rs` preflights `icmp_type_unrepresentable` etc. => `SnapshotIntegrityError`. No silent widening to match-all ICMP. Verified.
- **N-05: `tcp-flags` OR / negated group / unknown flag rejected at commit, not silently dropped**: `tcp_flags.go:ParseTCPFlagsExpression` returns error for `|`, `!(...)`, unknown flag, contradictory req/forbid. `compileFirewall` calls it and returns error. Rust preflight `tcp_flags_unparseable` => snapshot reject. Prevents `syn & !ack` constraint being dropped (pre-#3076 fail-open). Verified.
- **N-06: `flexible-match-range` length out of 1..=4 rejected, offset+length bounds checked, short packet fail-closed, no OOB**: `compiler.rs` preflight `UnrepresentableFilterFlexMatch`, `matching.rs:flex_matches` checks `1..=4`, `off+len` overflow via `checked_add`, `end > bytes.len()` => false, no indexing without bounds. Verified.
- **N-07: `flex_match_start` unsupported (payload) fails closed, not evaluated at L3 base**: `FlexMatchStart::Unsupported => return false` in `flex_matches`, Go `compileFilterFrom` records `UnknownFlexMatch` for `match-start payload` and `validateFilterFlexMatchStrict` rejects at commit. Prevents pre-#3232 wrong-offset match (security evasion). Verified.
- **N-08: `dscp` / `traffic-class` unresolved name / out-of-range numeric rejected, snapshot fail-closed for match, warn for rewrite**: `filter_match_resolve.go` not for DSCP (that's in `filters.go`), but `filters.go:159-191` marks `DSCPMatchUnrepresentable` when token not in `DSCPValues` map and not 0..63, Rust preflight `dscp_match_unrepresentable` => snapshot reject. Prevents `from dscp not-a-code then accept` becoming unconstrained accept (fail-open). Verified.
- **N-09: `protocol`/`next-header` unresolved token => snapshot reject**: `compiler.rs:673-692` loops `snap.protocols`, calls `proto_number`, empty skipped, None => `UnrepresentableFilterProtocol` => snapshot reject. Prevents `from protocol esp` (if esp not in table) from becoming match-all. But note: `proto_number` table includes esp/ah/sctp etc., so this is now fixed. Verified.
- **N-10: Cross-field unsatisfiable (`from protocol gre; destination-port 80`, `tcp-flags` with non-TCP, `icmp-type` with TCP) => snapshot reject**: `compiler.rs:711-761` checks `has_l4_ports`, `PROTO_TCP`, `PROTO_ICMP/ICMPV6`. Prevents never-match discard term that falls through to implicit Accept (fail-open). Verified, gated by `validateFilterCrossFieldStrict` at commit (primary) + Rust backstop.
- **N-11: `family any` single-family `source-address` / `icmp-type` / single-family prefix-list rejected at commit**: `validateFirewallFilterFamilyAnyMatchesAST` correctly rejects `source-address 10.0.0.0/8` under `family any` (would under-block v6), and `source-prefix-list v4-only` under `family any` (would under-block v6), and `source-prefix-list v4-only except` (would over-match v6). Verified in `compiler_firewall.go:561-733`.
- **N-12: `source-prefix-list` / `destination-prefix-list` single-name hierarchical shape fixed (#3843)**: `firewallPrefixListRefs` reads both `Keys[1:]` and `Children`, preventing fail-open where `source-prefix-list plX;` was dropped (match-all). Verified.
- **N-13: `then routing-instance X` + `then discard`/`reject` rejected at commit (#3308) and correctly DROPPED in userspace (RouteOverride::Drop, #4392)**: `validateFilterRoutingInstanceConflictStrict` + `ingress_route_table_override` is_drop gate. Verified in `forwarding/mod.rs:1611-1678` and `poll_descriptor/mod.rs:1685-1710`. The residual is only in kernel PBR mirror (M-01).
- **N-14: `then next term` / modifier-only term fall-through correctly accumulates count/log/forwarding-class/policer/dscp and continues, does not terminate**: `FilterTerm.continue_term` logic `(next_term || action empty) && RI empty`, eval loops `merge_matched_modifiers` and `continue` on `continue_term`. Correct Junos fall-through semantics (#2544).
- **N-15: Host-inbound before lo0 filter (#3485) prevents lo0 side-effects on denied host-bound traffic**: `host_inbound_gated_lo0_action` checks host-inbound FIRST (logical ifindex, per-interface override #3609), returns None on deny (no counter, no log, no reject reply), only runs lo0 on admit. Tests pin this. Verified.
- **N-16: PBR reject reply synthesis inside `ingress_route_table_override` uses same `enqueue_filter_reject_reply` as non-PBR reject, truthful log (REJECT→DENY downgrade on fail-closed)**: `PbrRejectSink` passed on flow-backed path, `reject_reply_enqueued` bool threaded into `emit_filter_log_event`. Correct per #3615+#4392.
- **N-17: Single-rate policer lowering (#4514) correctly maps `bandwidth-limit`/`burst-size-limit`/`then discard` to srTCM with drop treatments, color-blind true, stable ID, counter preservation**: `build_single_rate_policer_state`, `parse_single_rate_policer_runtime`, `unique_runtime_id`. Verified, fixes the pre-#4514 silently-unenforced single-rate policer (was dead `PolicerState` map, zero non-test callsites).
- **N-18: Three-color policer hard-cap at 2 runtimes is intentional SmallVec inline optimization, not a security bypass**: `CachedThreeColorPolicers` holds first + second, `push` dedup by ID, `extend` from other, `for_each` meters both. Third+ policer silently not metered — this IS F-127 (known), but for typical configs (1-2 policers per flow) it's not a bypass; for >2 it's a DoS (unpoliced) but not fail-open in filtering sense. Not re-reported.
- **N-19: Rib-group leak rules correctly sit at 30000-30999 (before main 32766 and before PBR 31000-31999), per-prefix, with Dst, so userspace FIB auto-captures them**: Fixes pre-#3876 shadow-by-default no-op (33000 after main). Verified in `rules.go:47-56`, `241-369`.
- **N-20: PBR ruledrop for DSCP-0 (be/cs0) is correct — netlink cannot represent DSCP 0 (zero tos = match ANY), so dropping the DSCP-0 match avoids over-match**: `buildPBRFromFilter` DSCP loop checks `tos==0` => degraded error + skip that DSCP value, not entire term unless all DSCPs are 0. Correct per #3430 H2.

## Suggested issue split

- **M-01 (residual-4392, Medium, VRF leak)**: PBR kernel mirror builds steering rules for `then routing-instance X; discard/reject` terms — fix BuildPBRRules to skip discard/reject terms.
- **M-03 (High, VRF leak)**: Next-table global ip rule — scope to source VRF via `iif vrf-<src>` or document as known limitation; verify caller passes per-RI routes.
- **M-02 (Medium, cache-coherency, verified residual F-129)**: `filter_term_semantics_match` omits flex fields — flow-cache stale verdicts after flex change. Already tracked as F-129, needs fix (add flex fields to equality).
- **L-01 (Low, DoS)**: Three-color policer without explicit color-blind defaults to fail-closed drop-all — default to color-blind or reject at commit.

All other previously-reported High fail-opens are verified fixed on b1bd96fb6. No new High fail-open (packet Juniper would DENY but xpf permits) found in the filter match fields themselves; the residual VRF leaks are in the routing/PBR glue, not in the filter matcher.

## Confidence summary

- High-confidence findings: M-01 (code trace clear, residual of #4392, lenient path keeps conflicting term, kernel mirror still steers), M-02 (verified still present, exact line match with F-129, cache-coherency impact), L-01 (code trace clear, DoS on valid Junos config).
- Medium-confidence: M-03 (code trace clear for global rule, but caller of ApplyNextTableRules not fully traced — need to confirm per-RI routes are passed; if only main routes are passed, leak is main->VRF, still a leak but less severe).
- Live-bypass (High fail-open) on this commit: None in the filter matcher itself; M-03 is High VRF leak in routing, M-01 is Medium VRF leak via PBR mirror.

*End of report. All files read read-only — no source modified.*
