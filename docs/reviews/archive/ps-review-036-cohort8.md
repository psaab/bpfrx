# xpf firewall deep audit — Cohort 8: Firewall filters + PBR + Routing — ps-review-036-cohort8

- Base commit: 33b891d11 (master HEAD, Merge PR #4563)
- Previous cohort 8 base: 8cd816e35 (ps-review-033)
- Diff since ps-review-033: 1 commit — navigatePath intermediate descent fix (#4562, display-only, not cohort 8 scope)
- Output path: /tmp/ps-review-036-cohort8.md
- Cohort: 8 — firewall filters + PBR + routing

## Duplicate-suppression summary

### Prior findings reviewed
- /tmp/all_findings.txt — 272 entries (F-001..F-272)
- /tmp/ps-review-033.md — prior cohort 8 audit (base 8cd816e35)
- /tmp/ps-review-024.md — detailed M-02/M-03 triage
- gh issue list --state all (30 open, ~200 closed)
- _Log.md recent entries
- ps-review-036-cohort2/3-4/5 — concurrent cohort reviews on same commit

### Dedup'd / not re-reported (CLOSED — do NOT re-report)
- #4562 navigatePath intermediate (DISPLAY-ONLY, fix verified on HEAD)
- #4559 deterministic NAT advisory, #4556 cli/api LOW (3 residuals), #4555 XDP EH 6 vs 8 (OPEN LOW but fail-closed parity)
- #4549 LOW batch, #4548 VRRP flap, #4547 ipsec DNS, #4546 WG, #4544 host-inbound dup (CLOSED), #4543 screen TLV (CLOSED)
- #4541 writeJSON (CLOSED), #4540 monitor keyword (CLOSED), #4539 session cache (CLOSED)
- #4535 three-color policer default (CLOSED, FIXED in b1bd96fb6), verified still present on 33b891d11
- #4534 PBR discard kernel-mirror (CLOSED, FIXED in b1bd96fb6), verified still present
- #4533 icmp_embed (OPEN, not cohort 8)
- #4526 DHCP, #4525 RA, #4524 monitor injection (HIGH, CLOSED), #4521 NAT pool, #4520 nat64 counter, #4519 nptv6, #4518 nat64 allocator, #4517 EH walkers
- #4515 warn-only, #4514 single-rate policer (CLOSED, FIXED), #4512 NAT64 HA-sync (OPEN, cohort 5)
- #4400/#4453/#4487 RST/FIN, #4399/#4438 NAT 1:N, #4392 PBR reject (CRITICAL, CLOSED), #4388, #4384, #3864, #3843 source-prefix-list, #4287 family any IPv6, #4426 family-any prefix-list, #3872 ECMP, #3855 RI table IDs, #3870 BGP AS, #3876 rib-group, #4071 GRE keepalive, #4015 df-bit, #3842 dup match/then, #3846 DeletePath, #3975 DeactivatePath, #3980 navigatePath terminal, #3982 RenamePath, #2419 bracket-list, #4149 unterminated
- #2387 bare 5-tuple (P0, cohort 6), #2399/#3205/#3307/#3723 filter match fields

### ps-review-033 triage — 2 NOT-MATERIAL (do NOT re-report as bugs)
- M-02 flex cache invalidation — moot because flow-cache DECLINE on flex (has_per_packet_l4_match_terms → flow_cache.rs:431-444 returns None), no cached verdict to go stale. Confirmed: filter_term_semantics_match omission is defense-in-depth only, not a live bug on current code. Already in all_findings as F-129 (UNKNOWN).
- M-03 next-table VRF leak — overstated (only caller passes main table static routes, per-RI routes handled via VRF mechanism; F-174 gap is known but not a live packet-forwarding bypass on current code). Confirmed on 33b891d11.

### Intentional divergences (NOT bugs — documented)
- next-table global ip rule (no iif) — documented, per-RI is F-174 (known gap)
- PBR ip rule has no iif selector — documented widening vs Junos per-interface FBF
- PBR kernel mirror fail-open VRF-steer (discard/reject) — FIXED #4534
- Rib-group Phase-1 only leaks into main — documented
- Flex match-start payload rejected at commit — intentional
- DSCP-0 cannot be represented as ip rule tos (zero = match ANY) — dropped with degraded warning
- Three-color policer only supports color-blind + discard — documented, FIXED #4535 default
- intrazone default-permit, host-originated junos-host, IPsec-passthrough-exempt, reject-all superset — documented
- flex_mask==0 → match-all F-236 — known, low, Go path safe (pre-masked value, defaults non-zero mask), hand-built snapshot only

### OPEN (NOT re-report unless materially new trace)
- #4559 deterministic NAT (OPEN, cohort 5), #4555 XDP EH (OPEN LOW, cohort 7), #4549 LOW batch, #4548, #4547, #4546, #4544 (CLOSED), #4543 (CLOSED), #4533 icmp_embed (OPEN, cohort 14), #4515 warn-only, #4512 NAT64 HA-sync (OPEN, cohort 5), #2387 bare 5-tuple (P0, cohort 6), #4146 junos-host, #3226, #2852, #2562, #4478, #4455, #4313, #4498, etc.

---

## Module / verdict-path inventory

| Module | File(s) | Role | Reviewed |
|---|---|---|---|
| Filter types / cache-key invariant | userspace-dp/src/filter/mod.rs | FilterTerm, FlexMatchStart, FilterState, counters, policer runtimes, TermMatchExtra | YES full |
| Filter compiler | userspace-dp/src/filter/compiler.rs | Snapshot → FilterState, fail-closed backstops, single-rate lowering | YES full |
| Filter matching | userspace-dp/src/filter/engine/matching.rs | term_matches_v4/v6, nets_match, port_match, per_packet_l4_matches, flex_matches | YES full |
| Filter eval | userspace-dp/src/filter/engine/eval.rs | evaluate_filter, lo0, input, output, routing-instance, NonRoutingCountPolicy | YES full |
| Filter cache-sensitive | userspace-dp/src/filter/engine/cache_sensitive.rs | cached TX replay, filter_term_semantics_match, DSCP/L4 family changed | YES full |
| Filter TX selection | userspace-dp/src/filter/engine/tx_selection.rs | TX-selection eval, policer merge, DSCP/police/FC | YES full |
| Filter policer (state) | userspace-dp/src/filter/policer.rs | ThreeColorPolicerState, refill, meter, treatments, single-rate lowering | YES full |
| Filter policer (app) | userspace-dp/src/filter/engine/policer.rs | apply_term_three_color_policer, apply_cached | YES full |
| Filter tests | userspace-dp/src/filter/tests.rs | 8000+ lines | sampled |
| AF_XDP poll filter | userspace-dp/src/afxdp/poll_descriptor/filter.rs | host_inbound_gated_lo0_action, filter_terminal, evaluate_non_pbr, DSCP/L4 re-eval, lo0 gate | YES full |
| Go firewall compiler | pkg/config/compiler_firewall.go | compileFirewall, family any dual-compile, family collision gate, family-any specific-match + PL-family gate | YES full |
| Go filter snapshot | pkg/dataplane/userspace/filters.go | buildFirewallFilterSnapshots, buildFilterTermSnapshots, resolvePrefixListAddrs, DSCP, flex | YES full |
| Go filter validators | pkg/config/compiler_validate_strict_filter.go | 12 strict gates (1660 lines) | YES full |
| Go routing | pkg/routing/rules.go | nextTableManager (100-199), ribGroupManager (30000-30999), pbrManager (31000-31999), BuildPBRRules, pbrTermL4, resolvePBRDirection | YES full |
| Forwarding PBR | userspace-dp/src/afxdp/forwarding/mod.rs:1529-1795 | ingress_route_table_override, RouteOverride::Drop, PbrRejectSink, should_cache_local_delivery | YES full |
| Policer types | pkg/config/types_system.go | PolicerConfig, ThreeColorPolicerConfig, FlexMatchConfig | YES |
| Routing compiler | pkg/config/compiler_routing.go | compileRoutingOptions, compileStaticRoutes, next-table, rib-group | YES partial |
| Next-table VRF | pkg/routing/vrf.go, routes.go | VRF lifecycle, route reading | YES partial |
| Frame / term_match_extra | userspace-dp/src/afxdp/frame/inspect.rs | term_match_extra_from_frame, is_fragment, l4_present, flex_l3/l4 | YES full |

---

## Module-by-module inspection log (including negatives)

### Filter matching — engine/matching.rs — VERIFIED CORRECT
- term_matches_v4/v6 correctly ANDs: protocol bitmap, nets_match (with except + constrained), port_match (with except + constrained), DSCP, per_packet_l4_matches, flex_matches. Correct.
- nets_match_v4/v6: constrained==false → true (match any). Empty nets + constrained → returns except (positive→false fail-closed, except→true match-all). Correct Junos empty-set semantics (#2506).
- port_match: constrained && PortMatcher::Any → false (fail-closed both directions, #3205). Otherwise matcher.matches(port) ^ except. Correct.
- per_packet_l4_matches: tcp-flags requires l4_present && protocol==TCP, checks required and forbidden masks (#3076). is_fragment L3-derived, NOT gated by l4_present. icmp-type/code require l4_present && is_icmp && in_set (prevents zero-byte spurious match #2362/#2449). flex via flex_matches. Correct.
- flex_matches: !flex_enabled → true; length 1..=4 else false (fail-closed); match-start Layer3/Layer4/Unsupported (Unsupported→false fail-closed #3232); base None → false (no L3/L4 bytes on cache/deferred path → fail-closed #3077); bounds check off+len ≤ base.len() → false on short (no OOB). Big-endian assemble then (val & mask) == value. Correct.
- No OOB, no panic, no bypass on truncated packets. Verified negative.
- F-236 (flex_mask==0→match-all): Go path pre-masks value (flex_value = value & mask), so mask=0 + value=0 → match-all is CORRECT Junos semantics. Hand-built snapshot with mask=0 + value!=0 impossible via Go (pre-masked). Defense-in-depth fix optional. Dedup'd.

### Filter compiler — compiler.rs — VERIFIED CORRECT
- parse_filter_state: MissingFilterRef → SnapshotIntegrityError fail-closed (#3296). Correct.
- parse_term preflights fail-closed for tcp_flags_unparseable (#3367), icmp_type/code unrepresentable (#3406), dscp_match_unrepresentable, dscp out-of-range (#3715), flex length (#3406). All → SnapshotIntegrityError, whole snapshot rejected. Correct.
- addr_is_real excludes empty/"any" from constrained — prevents match-nothing DoS. Correct.
- port_is_real excludes empty. Correct.
- Protocol resolution via proto_number SSOT. Empty skipped. Unresolvable → UnrepresentableFilterProtocol → snapshot reject fail-closed (#2505). Correct.
- Cross-field unsatisfiable (#3723): ports with non-TCP/UDP, tcp-flags with non-TCP, icmp with non-ICMP → UnsatisfiableFilterCrossField → snapshot reject. Correct.
- Single-rate lowering (#4514): bandwidth_bps/8, burst_bytes, discard_excess → treatments Green default, Yellow drop, Red drop. Color-blind true. Zero rate/burst → None → fail-closed if discard, skip if meter-only. Verified FIXED.
- Three-color shape supported: color_blind && (then_action empty or discard) — FIXED #4535 defaults color_blind=true when neither configured. Verified FIXED on 33b891d11.
- No OOB, no missing fail-closed except flex_mask (F-236, dedup'd).

### Filter cache-sensitive — cache_sensitive.rs — VERIFIED (1 DEFENSE-IN-DEPTH GAP, MOOT)
- filter_term_semantics_match compares: name, source/dest v4/v6, *_constrained, *_except, protocol_bitmap, protocol_match_enabled, source/dest_ports, *_port_constrained, *_port_except, dscp_bitmap, dscp_match_enabled, tcp_flags_*, is_fragment, icmp_*, action, continue_term, count, has_count, log, policer_name, three_color_policer (same_runtime_shape), routing_instance, forwarding_class, dscp_rewrite.
- Missing: flex_enabled, flex_offset, flex_length, flex_value, flex_mask, flex_match_start.
- HOWEVER: flex is cache-sensitive — flow-cache DECLINES for filters using flex (has_per_packet_l4_match_terms → flow_cache.rs:431-444 returns None), so stale cache cannot be replayed for flex filters. The flex omission in filter_term_semantics_match is MOOT for flow-cache correctness on current code.
- Flow-cache decline path: interface_input_filter_has_per_packet_l4_match(ingress_ifindex, is_v6) includes flex_enabled (via has_per_packet_l4_match), so flex filters correctly decline. Verified in flow_cache.rs:431-444.
- Rotation purge: input_per_packet_l4_filter_families_changed uses dscp_sensitive_filter_semantics_match → filter_term_semantics_match — flex field change would NOT trigger purge. But since flex filters never cache, no stale entry to purge. Moot.
- Still a defense-in-depth gap (if decline ever removed/bypassed), but NOT a live bug. Already in all_findings as F-129 (UNKNOWN). Dedup'd per task instruction.
- Deferred flex (to_static drops flex_l3/flex_l4 → None → fail-closed on deferred TX) — correct, not a bypass.

### Filter eval — engine/eval.rs — VERIFIED CORRECT
- evaluate_filter_ref_counted_v4/v6: first-match-wins, fall-through via continue_term, merge_matched_modifiers, record_filter_counter. Correct.
- evaluate_filter_ref_non_routing_counted + NonRoutingCountPolicy (#2620): Always vs OnlyTerminalNonAccept correctly avoids double-count and under-count. Verified.
- evaluate_filter_ref_routing_instance_counted: walks fall-through, captures acc_log (#2619), stamps lm.action (#2616). Correct.
- interface_filter_affects_route_lookup: precheck for PBR. Correct.

### Filter TX selection — engine/tx_selection.rs — VERIFIED CORRECT
- TX-selection eval, policer merge, DSCP/police/FC. Correct.
- Cached path uses TermMatchExtra::default() (no flex_l3/flex_l4) → flex terms fail-closed on cached replay. Safe because flow-cache declined for flex filters anyway.

### Filter policer — policer.rs — VERIFIED CORRECT
- ThreeColorPolicerState::sr_tcm/tr_tcm: zero rate/burst → Err, peak<committed → Err. Correct.
- meter: color-aware vs color-blind, srTCM/trTCM. Correct per RFC 2697/2698.
- refill: !initialized → init to burst, now_ns ≤ last_refill → no refill, elapsed*rate via u128 no overflow, capped_add. Correct.
- fail_closed: mode Unsupported → Red+drop. Correct.
- Single-rate lowering (#4514): bandwidth_bps/8, burst_bytes, discard_excess → treatments Green default, Yellow drop, Red drop. Color-blind true. Zero rate/burst → None → fail-closed if discard, skip if meter-only. Correct.
- CachedThreeColorPolicers hard-caps at 2 (first+second, push dedup by ID, third silently dropped). This is F-127 (known, tracked). Typical configs 1-2 policers per flow, not a security bypass. Low priority.
- Single-rate zero-bandwidth edge: parseBandwidthLimit returns 0 on garbage/empty → build_single_rate_policer_state returns None → if discard_excess then fail_closed (drop-all), else skip (meter-only has no action). Correct.

### AF_XDP poll filter — poll_descriptor/filter.rs — VERIFIED CORRECT
- host_inbound_gated_lo0_action: host-inbound FIRST (#3485), then lo0. Logical ifindex (#3609). Prevents lo0 side-effects on host-inbound denied. Tests pin deny→None+counter 0, admit→Reject+counter 1. Correct.
- filter_terminal: enqueue reject FIRST, then emit log with truthful action (#3615). Correct.
- evaluate_non_pbr_input_filter: count policy selection (#2620). Correct.
- evaluate_dscp_sensitive_input_filter_on_session_hit: re-evaluates DSCP + per-packet L4 on session hit (flow-cache decline path). Includes flex via has_per_packet_l4_match → re-eval on session hit. Correct.

### Go firewall compiler — compiler_firewall.go — VERIFIED CORRECT
- compileFirewall: handles hierarchical + flat-set shapes. family any → dests = both maps (#4287). Correct.
- validateFirewallFilterFamilyCollisionsAST: rejects same name across ≥2 non-inet6 families. Correct.
- validateFirewallFilterFamilyAnyMatchesAST: rejects family-specific matches + single-family prefix-list under family any. Correct per #4296+#4426.
- firewallPrefixListRefs: reads both leaf + block shapes. Correct per #3843.
- compileFilterFrom: accumulates all match fields. next-header → protocol (#3307). UnknownFrom recorded. Correct.
- compileFilterThen: handles leaf + block, forwarding-class, policer, routing-instance, count, log, loss-priority, dscp, next-term. TerminalActions collected. Correct.
- Three-color policer default (#4535): lines 171-178 default ColorBlind=true when neither configured. VERIFIED FIXED on 33b891d11.
- flex: byte-offset 0..255, bit-length 1..32, match-value/mask hex parsing with fail-closed on unparseable, default mask derivation, match-start layer-3/layer-4. Correct per #3203.
- is_fragment: leaf "is-fragment" → term.IsFragment = true. Correct.

### Go filter snapshot — filters.go — VERIFIED CORRECT
- buildFirewallFilterSnapshots: sorted, builds per filter. Correct.
- buildFilterTermSnapshots: handles all fields, tcp-flags via ParseTCPFlagsExpression, flex (length ceil, default 4, #3232 match-start), DSCP, icmp, ports, addresses. Correct.
- resolvePrefixListAddrs: drops any/empty, PL refs always constrain, any+except → sole except, mixed positive+except → positive-wins + warn (#3359), addrsAllMatchAny. Correct per #2506/#4338.
- buildPolicerSnapshots / buildThreeColorPolicerSnapshots: sorted. Correct.
- Single-rate policer: BandwidthBps = BandwidthLimit (bytes/sec, already /8), BurstBytes, DiscardExcess. Correct.
- flex: length = (BitLength+7)/8, default 4, oversized NOT capped (fail-closed via UnrepresentableFilterFlexMatch). Correct per #3406.

### Go firewall validators — compiler_validate_strict_filter.go — VERIFIED CORRECT
- 12 strict gates: policer ref, PL ref, RI ref, filter ref, RI direction, protocol, cross-field (#3723), actions, match values, flex, port-except, addr-except, addr literals, from-match, RI conflict, terminal conflict, DSCP. All verified.
- No new bypass. All gates properly strict on commit, lenient (warn) on load/peer-sync.

### Go routing — rules.go — VERIFIED CORRECT (1 DOCUMENTED LIMITATION)
- nextTableManager.Apply: priority 100-199, hard-cap 100, clears old, aggregates errors, installs `to <dst> lookup <table>` global ip rule. Correct per task instruction: "M-03 next-table VRF leak — overstated, only caller passes main table StaticRoutes, per-RI next-table never programmed (F-174 gap)" — verified on 33b891d11: daemon_apply.go passes only main table routes, NOT per-RI. Per-RI next-table is F-174 (known gap), not a live bug.
- ribGroupManager.Apply: per-prefix `to <connected-prefix> lookup <sourceTable>` pref 30000-30999, before main (32766) and before PBR (31000-31999). Correct per #3876.
- pbrManager.Apply: priority 31000-31999, clears old, installs `from <src> to <dst> tos <tos> ipproto <p> sport <sp> dport <dp> lookup <table>`. DSCP-0 dropped, TOS presence via TOSSet. PBR discard/reject skipped (#4534 FIXED). Correct.
- BuildPBRRules: only from attached input filters, DSCP×src×dst×proto×sport×dport cross-product, truncates to maxPBRRules (1000). pbrTermL4 classifies unrepresentable L4 predicates as fail-closed. Correct.
- validateFilterRoutingInstanceConflictStrict: rejects RI+discard/reject at commit. Lenient warns. FIXED #4534 kernel mirror. Verified FIXED on 33b891d11.

### Forwarding PBR — forwarding/mod.rs — VERIFIED CORRECT
- RouteOverride enum + ingress_route_table_override: resolves logical ingress ifindex, checks interface_filter_affects_route_lookup, builds TermMatchExtra (including is_fragment, l4_present, flex_l3/l4 via term_match_extra_from_frame), calls evaluate_interface_filter_routing_instance_event_counted, handles is_drop (Reject/Discard → Drop), synthesizes reject reply, emits filter log (#3615), returns Drop or Table. Correct per #4392.
- Callers in poll_descriptor match RouteOverride::Drop → recycle frame, skip route lookup. Correct.
- Both callers (session-miss flow-backed + flowless) verified: session-miss passes PbrRejectSink (can synthesize reply), flowless passes None (silent drop). Correct per #4392.

### Frame / term_match_extra — inspect.rs — VERIFIED CORRECT
- term_match_extra_from_frame: is_fragment L3-derived, NOT gated by l4_present. non_first_fragment → tcp_flags/icmp_type/code = 0, l4_present = false, flex_l4 = None. Correct per #2344/#2362/#2449/#3232.
- term_match_extra_from_frame_fwd: same contract for TX-selection / CoS path. Correct.
- term_match_extra_from_meta: is_fragment false (no frame), flex_l3/l4 None, l4_present = !is_icmp (so icmp-type/code terms fail closed on meta-only path). Correct.
- is_fragment on non-first fragment: is_any_fragment (is_fragment) stays true, is_non_first_fragment true → l4_present false, is_fragment true → is-fragment term matches non-first fragment. Correct.

### Policer — single-rate + three-color — VERIFIED CORRECT (FIXED #4514, #4535)
- Single-rate lowering: bandwidth_bps/8 already done in parseBandwidthLimit, burst_bytes, discard→Yellow drop/Red drop, color-blind true. Zero rate/burst → None → fail-closed if discard. Verified FIXED #4514.
- Three-color default: color-blind=true when neither color-blind nor color-aware configured. Verified FIXED #4535.
- Three-color shape: color_blind && (then_action empty or discard) — FIXED #4535 defaults color_blind=true, so unspecified case now supported (not fail-closed). Correct.

---

## Findings

### [F-001] CONFIRMED (known, still present, low): flex_mask == 0 turns flexible-match-range into match-all (F-236)

- Title: flex_mask == 0 accepted by Rust boundary — flexible-match-range becomes match-all
- Severity: Low (defense-in-depth, not live via Go path)
- Confidence: High
- Class: implementation-bug / defense-in-depth
- Evidence:
  ```rust
  // userspace-dp/src/filter/engine/matching.rs:149
  (val & term.flex_mask) == term.flex_value
  // When flex_mask == 0 and flex_value == 0: (any_val & 0) == 0 → ALWAYS true → match-all

  // userspace-dp/src/filter/compiler.rs:897-907
  flex_enabled: snap.flex_match.as_ref().is_some_and(|f| (1..=4).contains(&f.length)),
  flex_mask: snap.flex_match.as_ref().map_or(0, |f| f.mask),
  // No check: mask == 0 is accepted

  // pkg/config/compiler_firewall.go:1001-1014
  if fm.Mask == 0 {
      if fm.BitLength >= 32 { fm.Mask = 0xFFFFFFFF } else { fm.Mask = uint32(1)<<fm.BitLength - 1 }
  }
  // Go defaults mask when 0, so mask=0 never emitted via Go path
  ```
- Trace:
  1. Go path: match-value 0x0/0x0 (explicit mask 0, 32-bit) → Mask defaults to 0xFFFFFFFF (BitLength=32, Mask==0 → 0xFFFFFFFF), NOT 0. So mask 0 cannot be emitted via committed config.
  2. Hand-built snapshot: flex_match { offset:0, length:4, value:0, mask:0 } → flex_enabled=true, flex_mask=0, flex_value=0 → (any_val & 0) == 0 → true for ALL packets → term ALWAYS matches → if term is `then accept`, permits all (fail-open); if `then discard`, drops all (DoS, fail-closed).
  3. Go path pre-masks value: flex_value = value & mask, so value always 0 when mask is 0. So (val & 0) == 0 is correct for mask=0 + value=0 (Junos match-all for mask 0).
  4. However, hand-built snapshot with mask=0 and value!=0 would be (val & 0) == non-zero → 0 == non-zero → never matches → fail-open if term is discard. But Go path pre-masks, so this cannot happen via commit.
- Refutation attempted:
  - Verified Go defaults mask to non-zero when Mask==0 (BitLength 1..32 → mask = (1<<bits)-1 or 0xFFFFFFFF). So Go path never emits mask 0.
  - Junos semantics: mask 0 IS match-all by definition, so (val & 0) == 0 is CORRECT for intentional mask 0 configs. Not a bug for legitimate configs.
  - Hand-built/corrupt snapshot with mask=0 + value!=0 → never-matches → fail-open but requires crafted snapshot (not via commit). Could add backstop but low severity since Go path safe.
- Why it matters: Defense-in-depth — hand-built snapshot could cause match-all (if value 0) or match-nothing (if value !=0). Go path safe.
- Fix direction: In Rust compiler.rs: add `if snap.flex_match.as_ref().is_some_and(|f| f.mask == 0) { return Err(SnapshotIntegrityError::UnrepresentableFilterFlexMatch) }` OR in flex_matches: `if term.flex_mask == 0 { return term.flex_value == 0 }` (match-all when value also 0, never-matches otherwise — fail-closed).
- Labels: flex, firewall-filter, low-priority, defense-in-depth, known-issue
- Dedup note: CONFIRMED residual — already in all_findings.txt as F-236 "flex_mask==0→match-all". Known, tracked. On 33b891d11 still present as described. NOT a new finding. Per task: "flex_mask==0→match-all F-236 known but low" — CLOSED category but still present in code.
- Status: CONFIRMED (known, still present, low severity, Go path safe)

---

### [F-002] CONFIRMED (known, still present, low): filter_term_semantics_match omits flex_* fields — moot for flow-cache (decline path)

- Title: filter_term_semantics_match omits flex_* fields — moot because flow-cache DECLINE on flex
- Severity: Low (defense-in-depth, not live)
- Confidence: High
- Class: code-quality / defense-in-depth
- Evidence:
  ```rust
  // userspace-dp/src/filter/engine/cache_sensitive.rs:287-340 filter_term_semantics_match
  // Compares: name, source_v4/v6, dest_v4/v6, *_constrained, *_except, protocol_bitmap,
  //           protocol_match_enabled, source/dest_ports, *_port_constrained, *_port_except,
  //           dscp_bitmap, dscp_match_enabled, tcp_flags_mask/forbidden, is_fragment,
  //           icmp_type/code bitmaps+enabled, action, continue_term, count, has_count,
  //           log, policer_name, three_color_policer (same_runtime_shape),
  //           routing_instance, forwarding_class, dscp_rewrite
  // Missing: flex_enabled, flex_offset, flex_length, flex_value, flex_mask, flex_match_start

  // userspace-dp/src/filter/mod.rs:267-277 has_per_packet_l4_match()
  pub(crate) fn has_per_packet_l4_match(&self) -> bool {
      self.tcp_flags_mask.is_some() || self.tcp_flags_forbidden.is_some() ||
      self.is_fragment || self.icmp_type_match_enabled || self.icmp_code_match_enabled ||
      self.flex_enabled  // ← flex IS included here
  }

  // userspace-dp/src/afxdp/flow_cache.rs:431-444
  if interface_input_filter_has_per_packet_l4_match(...) { return None; } // DECLINE
  if interface_output_filter_has_per_packet_l4_match(...) { return None; } // DECLINE
  ```
- Trace:
  - Config: filter with `flexible-match-range byte-offset 0 bit-length 32 match-value 0x0800` then discard.
  - Flow-cache: has_per_packet_l4_match_terms = true (flex_enabled true) → flow_cache.rs DECLINES caching → no cached verdict to go stale.
  - filter_term_semantics_match omission: even if config changes flex from offset 0 to offset 6, the cache invalidation path would NOT detect change (flex fields not compared), BUT there is no cached entry to invalidate anyway (decline path).
  - dscp_sensitive_filter_semantics_match and input_per_packet_l4_filter_families_changed both use filter_term_semantics_match — flex omission propagates, but moot because flex filters never cache.
  - If decline ever removed (future optimization): stale verdicts could be replayed.
- Refutation attempted:
  - Verified has_per_packet_l4_match includes flex_enabled → has_per_packet_l4_match_terms true → flow-cache DECLINE. Confirmed in flow_cache.rs decline gates.
  - Task says: "M-02 flex cache invalidation — moot because flow-cache DECLINE on flex, no cached verdict to go stale (optional defense-in-depth, not a bug)" — explicitly triaged as NOT-MATERIAL.
  - Also in all_findings.txt as F-129: "filter_term_semantics_match omits all six flex_* fields". Known, tracked.
- Why it matters: Defense-in-depth — if decline path ever changes, flex field changes would not invalidate cache.
- Fix direction: Add flex_* fields to filter_term_semantics_match:
  ```rust
  && old.flex_enabled == new.flex_enabled
  && old.flex_offset == new.flex_offset
  && old.flex_length == new.flex_length
  && old.flex_value == new.flex_value
  && old.flex_mask == new.flex_mask
  && old.flex_match_start == new.flex_match_start
  ```
- Labels: filter, flex, cache-invalidation, defense-in-depth, low-priority, known-issue
- Dedup note: CONFIRMED residual — already in all_findings.txt as F-129 (UNKNOWN). Also ps-review-024 M-02 triaged as moot. NOT a new finding. Per task: explicitly triaged as NOT-MATERIAL.
- Status: CONFIRMED LOW (defense-in-depth, moot for now)

---

### [F-003] CONFIRMED (known, still present, low): CachedThreeColorPolicers hard-caps at 2 runtimes

- Title: CachedThreeColorPolicers hard-caps at 2 runtimes — third+ matched policer silently never meters
- Severity: Low (observable but not security bypass)
- Confidence: High
- Class: implementation-bug / observability-gap
- Evidence:
  ```rust
  // userspace-dp/src/filter/mod.rs:451-509 CachedThreeColorPolicers
  pub(crate) struct CachedThreeColorPolicers {
      first: Option<Arc<ThreeColorPolicerRuntime>>,
      second: Option<Arc<ThreeColorPolicerRuntime>>,
  }
  impl CachedThreeColorPolicers {
      pub(crate) fn push(&mut self, runtime: Arc<ThreeColorPolicerRuntime>) {
          // dedup by ID, then:
          if self.first.is_none() { self.first = Some(runtime); }
          else if self.second.is_none() { self.second = Some(runtime); }
          // third+ silently dropped — no warning, no error
      }
  }
  ```
- Trace: Config with 3 policer terms that all match (fall-through): `then policer p1 next term; then policer p2 next term; then policer p3 discard`. Cached path only meters p1 and p2, p3 never meters → rate-limit bypass for p3. Typical configs 1-2 policers per flow, so low impact.
- Refutation: F-127 in all_findings.txt (UNKNOWN). ps-review-024 N-18 triaged as intentional SmallVec inline optimization. Not a security bypass in filtering sense, but a rate-limit bypass for >2 policers.
- Why it matters: Rate-limit bypass for configs with >2 policers on one flow. Low priority — typical configs don't hit this.
- Fix direction: Use SmallVec or Vec for >2 policers, or validate at commit that no flow can match >2 policers.
- Labels: policer, rate-limit, low-priority, known-issue
- Dedup note: Already in all_findings.txt as F-127. ps-review-024 N-18 triaged. NOT a new finding.
- Status: CONFIRMED LOW (known, still present, not a security bypass)

---

### [F-004] NEGATIVE: Three-color policer default — FIXED #4535 verified on 33b891d11

- Title: Three-color policer color-blind default — FIXED
- Severity: N/A (fixed)
- Confidence: High
- Class: N/A — verified fixed
- Evidence:
  ```go
  // pkg/config/compiler_firewall.go:171-178 (FIXED #4535)
  for _, tcp := range fw.ThreeColorPolicers {
      if !tcp.ColorBlindConfigured && !tcp.ColorAwareConfigured {
          tcp.ColorBlind = true  // defaults to color-blind, matching Junos
      }
  }
  ```
- Trace: Verified fix on 33b891d11. Before: unspecified color mode → ColorBlind=false → snapshot_three_color_shape_supported false → fail_closed (drop all) → whole dataplane disarmed. After: defaults to true → supported → enforced.
- Status: FIXED (#4535) — verified on 33b891d11, no re-report.

---

### [F-005] NEGATIVE: PBR discard kernel-mirror — FIXED #4534 verified on 33b891d11

- Title: PBR discard/reject kernel mirror fail-open — FIXED
- Severity: N/A (fixed)
- Confidence: High
- Class: N/A — verified fixed
- Evidence:
  ```go
  // pkg/routing/rules.go:790-797 (FIXED #4534)
  if term.Action == "discard" || term.Action == "reject" {
      errs = append(errs, fmt.Errorf("... co-locates routing-instance with %q action; deny wins — no steering ip rule", ...))
      continue  // skip steering rule
  }
  ```
- Trace: Verified fix on 33b891d11. Before: PBR term with RI+discard built ip rule steering into VRF even though userspace dropped (fail-open VRF leak). After: Go commit gate rejects at strict, lenient warns, and buildPBRFromFilter skips steering (deny wins).
- Status: FIXED (#4534) — verified on 33b891d11, no re-report.

---

### [F-006] NEGATIVE: Single-rate policer unenforced — FIXED #4514 verified on 33b891d11

- Title: Single-rate policer silently unenforced — FIXED
- Severity: N/A (fixed)
- Evidence:
  ```rust
  // userspace-dp/src/filter/compiler.rs:94-113 #4514 lowering
  // Before #4514: state.policers map never consumed — then policer X was no-op
  // After #4514: build_single_rate_policer_state maps bandwidth/burst → srTCM
  ```
- Status: FIXED (#4514) — verified on 33b891d11.

---

### [F-007] NEGATIVE: Family any IPv6 arm — FIXED #4287+#4296+#4426 verified on 33b891d11

- Title: Family any dual-compile — FIXED
- Severity: N/A
- Evidence:
  ```go
  // pkg/config/compiler_firewall.go: dests = both maps for family any
  // validateFirewallFilterFamilyAnyMatchesAST: rejects single-family matches under any
  // validateFirewallFilterFamilyAnyMatchesAST: rejects single-family prefix-list under any (#4426)
  ```
- Status: FIXED — verified on 33b891d11, no new bypass.

---

### [F-008] NEGATIVE: is-fragment match on non-first fragment — correct, not a bug

- Title: is-fragment gated correctly — verified not a bug
- Severity: N/A
- Evidence:
  ```rust
  // userspace-dp/src/filter/engine/matching.rs: per_packet_l4_matches
  if term.is_fragment && !extra.is_fragment { return false; }
  // is_fragment is L3-derived, NOT gated by l4_present — correct
  // Non-first fragment still has is_fragment=true (from IP flags), so it matches is-fragment terms
  // term_match_extra_from_frame: is_fragment = is_any_fragment (includes first fragment)
  // non_first_fragment → l4_present=false but is_fragment stays true
  ```
- Status: NEGATIVE — correct implementation, no bug.

---

### [F-009] NEGATIVE: Flex match-start payload rejected at commit — intentional

- Title: Flex match-start payload rejected — intentional, not a bug
- Severity: N/A
- Evidence:
  ```go
  // pkg/config/compiler_firewall.go:931-936
  switch v {
  case "layer-3", "layer-4": fm.MatchStart = v
  default: term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-start "+v)
  }
  // → validateFilterFlexMatchStrict rejects at commit
  ```
- Status: NEGATIVE — intentional divergence, not a bug.

---

## Summary

### New findings on 33b891d11: 0 High/Med fail-opens

All HIGH/CRITICAL fail-opens previously reported (PBR reject #4392, PBR discard #4534, single-rate policer #4514, three-color default #4535, family any #4287/#4426, source-prefix-list #3843) are VERIFIED FIXED on 33b891d11.

The diff between ps-review-033 base (8cd816e35) and current HEAD (33b891d11) is a single display-only commit (#4562 navigatePath intermediate descent) that does not touch any cohort 8 code (filter, PBR, routing, policer, frame inspection). So all cohort 8 findings from ps-review-033 carry forward unchanged.

### Confirmed residuals (known, low severity, defense-in-depth):

- F-001: flex_mask==0 → match-all (F-236 known) — Go path safe (pre-masked value, defaults non-zero mask), hand-built snapshot only. Defense-in-depth fix optional.
- F-002: filter_term_semantics_match omits flex_* — moot because flow-cache DECLINE on flex (no cached verdict). F-129 known. Defense-in-depth gap, low priority.
- F-003: CachedThreeColorPolicers hard-caps at 2 — F-127 known, typical configs 1-2 policers. Low priority.

### Verified FIXED (no re-report):

- #4535 three-color policer default — FIXED (verified on 33b891d11)
- #4534 PBR discard kernel-mirror — FIXED (verified on 33b891d11)
- #4514 single-rate policer — FIXED (verified on 33b891d11)
- #4392 PBR reject — FIXED (verified on 33b891d11, RouteOverride::Drop + PbrRejectSink)
- #4287/#4426 family any — FIXED (verified on 33b891d11)
- #3843 source-prefix-list — FIXED (verified on 33b891d11)
- #4562 navigatePath — FIXED (display-only, verified)

### Verified negatives (fail-closed, correct):

- Empty address-except → fail-closed (match nothing for positive, match all for except) — correct
- Port-except unresolved → fail-closed (match nothing, #3205) — correct
- DSCP unresolvable → snapshot reject fail-closed (#3715) — correct
- Protocol unresolvable → snapshot reject fail-closed (#2505) — correct
- Cross-field unsatisfiable (ports with non-TCP/UDP, tcp-flags with non-TCP, icmp with non-ICMP) → snapshot reject (#3723) — correct
- Flex length out of 1..=4 → snapshot reject (#3406) — correct
- Flex match-start Unsupported → fail-closed (#3232) — correct
- TCP flags unparseable → snapshot reject (#3367) — correct
- ICMP type/code unrepresentable → snapshot reject (#3406) — correct
- LSP / filter ref missing → snapshot reject (#3296) — correct
- Flex is cache-sensitive (decline) → no stale cache — correct
- DSCP/L4 per-packet re-eval on session hit → correct
- is-fragment on non-first fragment → correct (L3-derived, not gated by l4_present)
- Non-first fragment L4 terms fail closed (tcp-flags, icmp-type/code, flex L4) → correct
- Truncated ICMP fail-closed (#2449) → correct
- Output filter needs_tx_eval flag → correct
- Family any specific-match gate → correct
- Prefix-list family gate (#4426) → correct
- RI conflict gate (#3308) → correct
- Terminal conflict gate (#4375) → correct
- RI direction gate (input-only FBF) → correct
- Port-except mutual exclusion (#3297) → correct
- Address-except mixed (#3359/#4338) → correct
- Address literals family check (#3433) → correct
- From-match strict (#3307) → correct
- DSCP strict (#3309) → correct
- Single-rate zero rate/burst → fail-closed if discard, skip if meter-only — correct
- Three-color unsupported shape → fail-closed drop-all — correct

### Intentional divergences (NOT bugs):

- PBR no iif (global rule) — documented widening
- Next-table global (main table only) — documented, per-RI is F-174 gap
- Rib-group Phase-1 only into main — documented
- Flex match-start payload rejected at commit — intentional
- DSCP-0 ip rule unrepresentable (dropped) — documented
- Three-color only color-blind+discard — documented
- Intrazone default-permit, host-originated junos-host, IPsec-passthrough-exempt — documented
- flex_mask==0 → match-all — known low, Go path safe

---

## Suggested issue split: NONE (no new High/Med fail-opens)

All cohort 8 code on 33b891d11 is in good shape. The 3 confirmed residuals are low/defense-in-depth/known gaps, not warranting new issues unless triaged as hardening follow-ups.

Diff from ps-review-033 is display-only (#4562), so no new cohort 8 findings vs prior audit is expected and confirmed.
