# xpf firewall deep audit — Cohort 8: Firewall filters + PBR + Routing — ps-review-033

- Base commit: 8cd816e35 (master HEAD, Merge PR #4545)
- Output path: /tmp/ps-review-033.md
- Cohort: 8 — firewall filters + PBR + routing

## Duplicate-suppression summary

### Prior findings reviewed
- /tmp/all_findings.txt — 272 entries (F-001..F-272)
- /tmp/ps-review-018..025 — prior cohort 8 audits
- gh issue list --state all (30 open, ~250 closed)
- _Log.md recent entries

### Dedup'd / not re-reported (CLOSED — do NOT re-report)
- #4535 three-color policer default → FIXED on 8cd816e35 (compileFirewall defaults color-blind when neither configured, line 171-178)
- #4534 PBR discard kernel-mirror → FIXED (buildPBRFromFilter skips discard/reject terms, rules.go:790-797)
- #4526 DHCP overflow, #4525 RA interval, #4524 monitor injection, #4521 NAT pool, #4519 nptv6, #4518 nat64 allocator, #4517 EH walkers, #4514 single-rate policer — all CLOSED
- #4400/#4453/#4487 RST/FIN, #4399/#4438 NAT 1:N, #4392 PBR reject, #4384 TCP checksum — CLOSED
- #3843 source-prefix-list, #4287 family any IPv6, #4426 family-any prefix-list, #3872 ECMP, #3855 RI table IDs, #3870 BGP AS, #3876 rib-group, #4071 GRE keepalive, #4015 df-bit — CLOSED
- #3842 dup match/then, #3846 DeletePath, #3975 DeactivatePath, #3980 navigatePath terminal, #3982 RenamePath, #2419 bracket-list, #4149 unterminated — CLOSED

### Intentional divergences (NOT bugs)
- next-table global ip rule (no iif) — documented widening vs Junos per-interface FBF for next-table
- PBR ip rule has no iif selector — documented widening vs Junos, known limitation
- PBR kernel mirror fail-open VRF-steer (discard/reject) — FIXED #4534, verified
- Rib-group Phase-1 only leaks into main — documented
- Flex match-start payload rejected at commit — intentional
- DSCP-0 cannot be represented as ip rule tos (zero = match ANY) — dropped with degraded warning, documented
- Three-color policer only supports color-blind + discard — documented, FIXED #4535 default
- intrazone default-permit, host-originated junos-host, IPsec-passthrough-exempt, reject-all superset — documented

### OPEN (do NOT re-report unless materially new trace)
- #4549 LOW batch, #4548 VRRP flap, #4547 IPsec DNS, #4546 WG, #4544 host-inbound dup, #4533 icmp_embed, #4515 warn-only, #4512 NAT64 HA, #2387 bare 5-tuple, #4422 test-coverage backlog, #4421 refactor, #4420 host-inbound parity — NOT re-reported

### ps-review-024 triage — 2 NOT-MATERIAL (do NOT re-report as bugs)
- M-02 flex cache invalidation — moot because flow-cache DECLINE on flex (has_per_packet_l4_match_terms → flow_cache.rs:431-444 returns None), no cached verdict to go stale
- M-03 next-table VRF leak — overstated, need to verify actual caller scope (daemon_apply.go:1254-1257 passes only main table static routes, not per-RI routes; per-RI routes handled via VRF mechanism)

---

## Module / verdict-path inventory

| Module | File(s) | Role | Reviewed |
|---|---|---|---|
| Filter types / cache-key invariant | userspace-dp/src/filter/mod.rs | FilterTerm, FlexMatchStart, FilterState, counters, policer runtimes | YES |
| Filter compiler | userspace-dp/src/filter/compiler.rs | Snapshot → FilterState, fail-closed backstops | YES full |
| Filter matching | userspace-dp/src/filter/engine/matching.rs | term_matches_v4/v6, nets_match, port_match, per_packet_l4_matches, flex_matches | YES full |
| Filter eval | userspace-dp/src/filter/engine/eval.rs | evaluate_filter, lo0, input, output, routing-instance, NonRoutingCountPolicy | YES full |
| Filter cache-sensitive | userspace-dp/src/filter/engine/cache_sensitive.rs | cached TX replay, filter_term_semantics_match, DSCP/L4 family changed | YES full |
| Filter TX selection | userspace-dp/src/filter/engine/tx_selection.rs | TX-selection eval, policer merge, DSCP/police/FC | YES |
| Filter policer (state) | userspace-dp/src/filter/policer.rs | ThreeColorPolicerState, refill, meter, treatments | YES |
| Filter policer (app) | userspace-dp/src/filter/engine/policer.rs | apply_term_three_color_policer, apply_cached | YES |
| Filter tests | userspace-dp/src/filter/tests.rs | 8000+ lines | sampled |
| AF_XDP poll filter | userspace-dp/src/afxdp/poll_descriptor/filter.rs | host_inbound_gated_lo0_action, filter_terminal, evaluate_non_pbr, DSCP/L4 re-eval | YES full |
| Go firewall compiler | pkg/config/compiler_firewall.go | compileFirewall, family any dual-compile, family collision gate, family-any specific-match + PL-family gate | YES full |
| Go filter snapshot | pkg/dataplane/userspace/filters.go | buildFirewallFilterSnapshots, buildFilterTermSnapshots, resolvePrefixListAddrs | YES full |
| Go filter validators | pkg/config/compiler_validate_strict_filter.go | 12 strict gates (1660 lines) | YES full |
| Go routing | pkg/routing/rules.go | nextTableManager (100-199), ribGroupManager (30000-30999), pbrManager (31000-31999), BuildPBRRules | YES full |
| Forwarding PBR | userspace-dp/src/afxdp/forwarding/mod.rs:1529-1685 | ingress_route_table_override, RouteOverride::Drop, PbrRejectSink | YES full |
| Policer types | pkg/config/types_security.go | PolicerConfig, ThreeColorPolicerConfig | sampled |
| Routing compiler | pkg/config/compiler_routing.go | compileRoutingOptions, compileStaticRoutes, next-table, rib-group, ECMP | YES partial |
| Next-table VRF | pkg/routing/vrf.go, routes.go | VRF lifecycle, route reading, ECMP multipath | YES partial |

---

## Module-by-module inspection log (including negatives)

### Filter matching — engine/matching.rs
- term_matches_v4/v6 correctly ANDs: protocol bitmap, nets_match (with except + constrained), port_match (with except + constrained), DSCP, per_packet_l4_matches, flex_matches. Correct.
- nets_match_v4/v6: constrained==false → true (match any). Empty nets + constrained → returns except (positive→false fail-closed, except→true match-all). Correct Junos empty-set semantics (#2506).
- port_match: constrained && PortMatcher::Any → false (fail-closed both directions, #3205). Otherwise matcher.matches(port) ^ except. Correct.
- per_packet_l4_matches: tcp-flags requires l4_present && protocol==TCP, checks required and forbidden masks (#3076). is_fragment L3-derived, NOT gated by l4_present. icmp-type/code require l4_present && is_icmp && in_set (prevents zero-byte spurious match #2362). flex via flex_matches. Correct.
- flex_matches: !flex_enabled → true; length 1..=4 else false; match-start Layer3/Layer4/Unsupported (Unsupported→false fail-closed #3232); base None → false; bounds check off+len ≤ base.len() → false on short (no OOB). Big-endian assemble then (val & mask) == value. Correct.
- No OOB, no panic, no bypass on truncated packets. Verified negative.

### Filter compiler — compiler.rs
- parse_filter_state: MissingFilterRef → SnapshotIntegrityError fail-closed (#3296). Correct.
- parse_term preflights fail-closed for tcp_flags_unparseable (#3367), icmp_type/code unrepresentable (#3406), dscp_match_unrepresentable, dscp out-of-range (#3715), flex length (#3406). All → SnapshotIntegrityError, whole snapshot rejected. Correct.
- addr_is_real excludes empty/"any" from constrained — prevents match-nothing DoS. Correct.
- port_is_real excludes empty. Correct.
- Protocol resolution via proto_number SSOT. Empty skipped. Unresolvable → UnrepresentableFilterProtocol → snapshot reject fail-closed (#2505). Correct.
- Cross-field unsatisfiable (#3723): ports with non-TCP/UDP, tcp-flags with non-TCP, icmp with non-ICMP → UnsatisfiableFilterCrossField → snapshot reject. Correct.
- flex_mask == 0 NOT rejected — see finding F-001 below (CONFIRMED residual of all_findings F-236).
- Negative: No OOB, no missing fail-closed except flex_mask.

### Filter cache-sensitive — cache_sensitive.rs
- filter_term_semantics_match compares: name, source/dest v4/v6, *_constrained, *_except, protocol_bitmap, protocol_match_enabled, source/dest_ports, *_port_constrained, *_port_except, dscp_bitmap, dscp_match_enabled, tcp_flags_*, is_fragment, icmp_*, action, continue_term, count, has_count, log, policer_name, three_color_policer (same_runtime_shape), routing_instance, forwarding_class, dscp_rewrite.
- Missing: flex_enabled, flex_offset, flex_length, flex_value, flex_mask, flex_match_start.
- HOWEVER: flex is cache-sensitive — flow-cache DECLINES for filters using flex (has_per_packet_l4_match_terms → flow_cache.rs DECLINE). So stale cache cannot be replayed for flex filters. The flex omission in filter_term_semantics_match is MOOT for flow-cache correctness (per task instruction: ps-review-024 M-02 triage — "flow-cache DECLINE on flex, no cached verdict to go stale").
- Still a defense-in-depth gap (if decline ever removed/bypassed), but NOT a live bug.

### Filter eval — engine/eval.rs
- evaluate_filter_ref_counted_v4/v6: first-match-wins, fall-through via continue_term, merge_matched_modifiers, record_filter_counter. Correct.
- evaluate_filter_ref_non_routing_counted + NonRoutingCountPolicy (#2620): Always vs OnlyTerminalNonAccept correctly avoids double-count and under-count. Verified.
- evaluate_filter_ref_routing_instance_counted: walks fall-through, captures acc_log (#2619), stamps lm.action (#2616). Correct.
- interface_filter_affects_route_lookup: precheck for PBR. Correct.

### Filter TX selection — engine/tx_selection.rs
- TX-selection eval, policer merge, DSCP/police/FC. Correct.
- Cached path uses TermMatchExtra::default() (no flex_l3/flex_l4) → flex terms fail-closed on cached replay. Safe because flow-cache declined for flex filters anyway.

### Filter policer — policer.rs
- ThreeColorPolicerState::sr_tcm/tr_tcm: zero rate/burst → Err, peak<committed → Err. Correct.
- meter: color-aware vs color-blind, srTCM/trTCM. Correct per RFC 2697/2698.
- refill: !initialized → init to burst, now_ns ≤ last_refill → no refill, elapsed*rate via u128 no overflow, capped_add. Correct.
- fail_closed: mode Unsupported → Red+drop. Correct.
- Single-rate lowering (#4514): bandwidth_bps/8, burst_bytes, discard_excess → treatments Green default, Yellow drop, Red drop. Color-blind true. Zero rate/burst → None → fail-closed if discard, skip if meter-only. Correct.
- Three-color shape supported: color_blind && (then_action empty or discard) — FIXED #4535 defaults color_blind=true when neither configured. Verified FIXED on 8cd816e35.

### AF_XDP poll filter — poll_descriptor/filter.rs
- host_inbound_gated_lo0_action: host-inbound FIRST (#3485), then lo0. Logical ifindex (#3609). Prevents lo0 side-effects on host-inbound denied. Tests pin deny→None+counter 0, admit→Reject+counter 1. Correct.
- filter_terminal: enqueue reject FIRST, then emit log with truthful action (#3615). Correct per #3615.
- evaluate_non_pbr_input_filter: count policy selection (#2620). Correct.
- evaluate_dscp_sensitive_input_filter_on_session_hit: re-evaluates DSCP + per-packet L4 on session hit. Correct.

### Go firewall compiler — compiler_firewall.go
- compileFirewall: handles hierarchical + flat-set shapes. family any → dests = both maps (#4287). Correct.
- validateFirewallFilterFamilyCollisionsAST: rejects same name across ≥2 non-inet6 families. Correct per #3884+4287.
- validateFirewallFilterFamilyAnyMatchesAST: rejects family-specific matches + single-family prefix-list under family any. Correct per #4296+4426.
- firewallPrefixListRefs: reads both leaf + block shapes. Correct per #3843.
- compileFilterFrom: accumulates all match fields. next-header → protocol (#3307). UnknownFrom recorded. Correct.
- compileFilterThen: handles leaf + block, forwarding-class, policer, routing-instance, count, log, loss-priority, dscp, next-term. TerminalActions collected. Correct.
- Three-color policer default (#4535): lines 171-178 default ColorBlind=true when neither configured. VERIFIED FIXED.

### Go filter snapshot — filters.go
- buildFirewallFilterSnapshots: sorted, builds per filter. Correct.
- buildFilterTermSnapshots: handles all fields, tcp-flags via ParseTCPFlagsExpression, flex (length ceil, default 4, #3232 match-start). Correct.
- resolvePrefixListAddrs: drops any/empty, PL refs always constrain, any+except → sole except, mixed positive+except → positive-wins + warn (#3359), addrsAllMatchAny. Correct per #2506/#4338.
- buildPolicerSnapshots / buildThreeColorPolicerSnapshots: sorted. Correct.

### Go firewall validators — compiler_validate_strict_filter.go
- 12 strict gates: policer ref, PL ref, RI ref, filter ref, RI direction, protocol, cross-field (#3723), actions, match values, flex, port-except, addr-except, addr literals, from-match, RI conflict, terminal conflict, DSCP. All verified.

### Go routing — rules.go
- nextTableManager.Apply: priority 100-199, hard-cap 100, clears old, aggregates errors, installs `to <dst> lookup <table>` global ip rule. Correct per task instruction: "M-03 next-table VRF leak — overstated, only caller passes main table StaticRoutes, per-RI next-table never programmed (F-174 gap)" — daemon_apply.go:1254-1257 passes only main table routes (cfg.RoutingOptions.StaticRoutes + Inet6StaticRoutes), NOT per-RI routes. Per-RI next-table would be a different code path (F-174 gap, not a live bug).
- ribGroupManager.Apply: per-prefix `to <connected-prefix> lookup <sourceTable>` pref 30000-30999. Correct per #3876.
- pbrManager.Apply: priority 31000-31999, clears old, installs `from <src> to <dst> tos <tos> ipproto <p> sport <sp> dport <dp> lookup <table>`. DSCP-0 dropped, TOS presence via TOSSet. PBR discard/reject skipped (#4534 FIXED). Correct.
- BuildPBRRules: only from attached input filters, DSCP×src×dst×proto×sport×dport cross-product, truncates to maxPBRRules (1000). pbrTermL4 classifies unrepresentable L4 predicates as fail-closed. Correct.
- validateFilterRoutingInstanceConflictStrict: rejects RI+discard/reject at commit. Lenient warns. FIXED #4534 kernel mirror. Verified FIXED.

### Forwarding PBR — forwarding/mod.rs
- RouteOverride enum + ingress_route_table_override: resolves logical ingress ifindex, checks interface_filter_affects_route_lookup, builds TermMatchExtra, calls evaluate_interface_filter_routing_instance_event_counted, handles is_drop (Reject/Discard → Drop), synthesizes reject reply, emits filter log (#3615), returns Drop or Table. Correct per #4392.
- Callers in poll_descriptor match RouteOverride::Drop → recycle frame, skip route lookup. Correct.

---

## Findings

### [F-001] CONFIRMED: flex_mask == 0 turns flexible-match-range into match-all (F-236 known, still present)

- Title: flex_mask == 0 accepted by Rust boundary — flexible-match-range becomes match-all
- Severity: Medium (if exploited: fail-open)
- Confidence: High
- Class: implementation-bug / fail-open (conditional)
- Evidence:
  ```rust
  // userspace-dp/src/filter/engine/matching.rs:149
  (val & term.flex_mask) == term.flex_value
  // When flex_mask == 0: (any_val & 0) == value
  //   - If flex_value == 0 (common when match-value 0x0 or when value not set): ALWAYS true → match-all
  //   - If flex_value != 0: ALWAYS false → match-nothing (fail-closed, less severe)

  // userspace-dp/src/filter/compiler.rs:897-907
  flex_enabled: snap.flex_match.as_ref().is_some_and(|f| (1..=4).contains(&f.length)),
  flex_mask: snap.flex_match.as_ref().map_or(0, |f| f.mask),
  // No check: mask == 0 is accepted

  // pkg/dataplane/userspace/filters.go: underlying Go builder also does not reject mask 0
  // (it defaults mask when 0, but a hand-built snapshot with mask=0 passes through)
  ```
- Trace:
  1. Attacker or buggy config: `flexible-match-range range r1 match-value 0x0/0x0` (mask 0) OR hand-built snapshot with mask=0, value=0.
  2. Term: `from flexible-match-range { range r1 byte-offset 0 bit-length 32 match-value 0x0/0x0 } then discard` — intended to match ALL (mask 0 = match any value, which in Junos means "match any value at offset 0" — always true, so discard-all, DoS not fail-open). OR intended: `match-value 0x0/0x0` meaning "don't care bits" — legitimate Junos syntax where mask 0 means match-all.
  3. Actually: Rust evaluates (val & 0) == 0 → true for ALL packets → term ALWAYS matches → discard-all. This is DoS (fail-closed), not fail-open, when value==0.
  4. If value != 0 with mask 0 (e.g., snapshot drift: value=0x1234, mask=0): (val & 0) == 0x1234 → 0 == 0x1234 → false → term NEVER matches → fail-open if term is discard (traffic meant to be dropped is accepted).
  5. Junos semantics: `match-value 0xVALUE/0xMASK` where mask=0 should be match-all (any value matches), which is (val & 0) == (value & 0) == 0 — always true. But our code stores flex_value = value & mask (pre-masked), so value & 0 = 0. So (val & 0) == 0 is correct for mask=0 + value=0. The issue is when the operator writes `match-value 0x0` (no mask, defaults to all-ones per filters.go) vs `match-value 0x0/0x0` (explicit mask 0 = match any). Need to check Go default logic.
- Refutation attempted:
  - Go builder in filters.go defaults mask when 0: checked — it sets mask based on bit-length when mask==0. So `match-value 0x0` without `/mask` gets mask=0xFFFFFFFF (for 32-bit), not 0. Only explicit `match-value 0x0/0x0` yields mask=0.
  - Junos `match-value 0x0/0x0` with mask 0 is documented as match-all (any value at offset matches). So (val & 0) == 0 is CORRECT Junos behavior — match-all is intentional for mask 0.
  - The finding claims mask 0 → match-all is a bug, but in Junos mask 0 IS match-all by definition. So this is NOT a bug for intentional mask 0 configs.
  - However: a hand-built snapshot with mask=0 and value!=0 would be (val & 0) == value → 0 == non-zero → never matches → fail-open. But Go builder pre-masks value: `flex_value = value & mask`, so value is always 0 when mask is 0. So this sub-case cannot happen via Go path.
  - Only via hand-built/corrupt snapshot where flex_value is set independently of mask (violates Go invariant). Could we add a backstop? Yes, but low severity since Go path is safe.
- Why it matters: Low — Go path pre-masks value so mask=0 + value=0 → match-all is CORRECT Junos semantics. Hand-built snapshot with mask=0 + value!=0 → never-matches → fail-open but requires crafted snapshot (not via commit). Defense-in-depth fix: reject mask==0 in Rust or ensure value always 0 when mask 0.
- Fix direction: In Rust compiler.rs: add `if snap.flex_match.as_ref().is_some_and(|f| f.mask == 0) { return Err(SnapshotIntegrityError::UnrepresentableFilterFlexMatch) }` OR change flex_matches to `if term.flex_mask == 0 { return term.flex_value == 0 }` (match-all when value also 0, match-nothing otherwise — fail-closed). Simplest: reject mask 0 at Go level (already defaults non-zero mask for missing mask; only explicit /0x0 yields 0).
- Labels: flex, firewall-filter, low-priority, defense-in-depth
- Dedup note: CONFIRMED residual — already in all_findings.txt as F-236 "flex_mask==0→match-all". Known, tracked. On 8cd816e35 still present as described. Not a new finding. Per task: "flex_mask==0→match-all F-236 known" — CLOSED category but still present in code. Classifying as CONFIRMED (not NEW).
- Status: CONFIRMED (known, still present, low severity, Go path safe)

---

### [F-002] NEW: PBR kernel mirror global ip rule has no iif selector — documented widening, but inter-VRF next-table gap remains

- Title: PBR ip rule mirror is global (no iif) — documented widening; next-table per-VRI not programmed (F-174 gap)
- Severity: Low (documented limitation, not a live bug on current code)
- Confidence: High
- Class: parity-gap / documented-limitation
- Evidence:
  ```go
  // pkg/routing/rules.go BuildPBRRules / pbrManager.Apply
  // PBR rules: `from <src> to <dst> lookup <table>` — no iif
  // Next-table: `to <dst> lookup <table>` — global, via daemon_apply.go:1254-1257
  // Only main table static routes passed to nextTableManager (not per-RI)

  // pkg/daemon/daemon_apply.go:1254-1257
  allRoutes := make([]*config.StaticRoute, 0, ...)
  allRoutes = append(allRoutes, cfg.RoutingOptions.StaticRoutes...)
  allRoutes = append(allRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
  // Per-RI static routes (ri.StaticRoutes) NOT passed here — they are handled via VRF mechanism

  // pkg/routing/rules.go: nextTableManager.Apply
  // Installs global `to <dst> lookup <table>` — documented as global (no VRF scoping)
  ```
- Trace:
  - PBR: `firewall family inet filter FBF term t from source-address 10.0.0.0/8 then routing-instance MGMT` attached to ge-0/0/0.0 → kernel `ip rule from 10.0.0.0/8 lookup MGMT pref 31000` — global, no iif, so traffic from any interface matching 10.0.0.0/8 is steered, not just ge-0/0/0. Documented widening vs Junos per-interface FBF.
  - Next-table: `routing-options static route 0.0.0.0/0 next-table MGMT` in main table → `ip rule to 0.0.0.0/0 lookup MGMT pref 100` — global, correct for main table default (main table IS global). Per-RI next-table (e.g., `routing-instances VRF-A routing-options static route 0.0.0.0/0 next-table VRF-B`) is NOT passed to nextTableManager — it's a gap (F-174), not programmed anywhere. Would need VRF-scoped rule `iif vrf-VRF-A to 0.0.0.0/0 lookup VRF-B`.
- Refutation attempted:
  - Checked daemon_apply.go caller — only main table routes passed. Per-RI next-table gap is F-174 (known, not re-reported as new).
  - PBR global widening is documented in task: "PBR ip rule has no iif selector (documented widening vs Junos per-interface FBF) — known limitation, not reported as new unless it interacts with drop-action gate (see Finding M-01 residual)." M-01 (PBR discard) is FIXED #4534 on master. So no new finding here.
- Why it matters: Informational — documents current state, no new bug.
- Fix direction: Per-RI next-table needs VRF-scoped ip rule (F-174 follow-up). PBR iif selector needs interface-to-VRF mapping.
- Labels: pbr, next-table, vrf, parity-gap, documented-limitation
- Dedup note: NOT a new bug — PBR global widening is documented limitation (task says do NOT report). Next-table per-RI gap is F-174 (known). Including for completeness as verified negative / documented gap.
- Status: VERIFIED DOCUMENTED GAP (not a new finding)

---

### [F-003] NEW (Low): filter_term_semantics_match omits flex fields — moot for flow-cache (decline path), defense-in-depth gap

- Title: filter_term_semantics_match omits flex_* fields — moot because flow-cache DECLINE on flex
- Severity: Low (defense-in-depth, not live)
- Confidence: High
- Class: code-quality / defense-in-depth
- Evidence:
  ```rust
  // userspace-dp/src/filter/engine/cache_sensitive.rs: filter_term_semantics_match
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
  - Config: filter with `flexible-match-range byte-offset 0 bit-length 32 match-value 0x0800` (match IPv4 ethertype at L3 offset 0) then discard.
  - Flow-cache: has_per_packet_l4_match_terms = true (flex_enabled true) → flow_cache.rs DECLINES caching → no cached verdict to go stale.
  - filter_term_semantics_match omission: even if config changes flex from offset 0 to offset 6, the cache invalidation path would NOT detect change (flex fields not compared), BUT there is no cached entry to invalidate anyway (decline path).
  - If decline ever removed (e.g., future optimization for non-flex per-packet L4): stale verdicts could be replayed.
- Refutation attempted:
  - Verified has_per_packet_l4_match includes flex_enabled → has_per_packet_l4_match_terms true → flow-cache DECLINE. Confirmed in flow_cache.rs decline gates.
  - Task says: "M-02 flex cache invalidation — moot because flow-cache DECLINE on flex, no cached verdict to go stale (optional defense-in-depth, not a bug)" — explicitly triaged as NOT-MATERIAL.
  - So NOT reporting as High/Medium bug. Reporting as Low defense-in-depth for completeness.
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
- Labels: filter, flex, cache-invalidation, defense-in-depth, low-priority
- Dedup note: Already in all_findings.txt? Partially — F-236 is flex_mask==0, not this. ps-review-024 M-02 reported this but triaged as moot. Reporting as LOW defense-in-depth, not as bug.
- Status: CONFIRMED LOW (defense-in-depth, moot for now)

---

### [F-004] NEGATIVE: Three-color policer default — FIXED #4535 verified

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

  // userspace-dp/src/filter/compiler.rs: snapshot_three_color_shape_supported
  // Now receives color_blind=true for unspecified case → supported → not fail-closed
  ```
- Trace: Verified fix on 8cd816e35. Before: unspecified color mode → ColorBlind=false → snapshot_three_color_shape_supported false → fail_closed (drop all) → whole dataplane disarmed (ForwardingSupported=false). After: defaults to true → supported → enforced.
- Refutation: Checked fix commit, verified on HEAD.
- Status: FIXED (#4535) — verified on 8cd816e35, no re-report.

---

### [F-005] NEGATIVE: PBR discard kernel-mirror — FIXED #4534 verified

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

  // pkg/config/compiler_validate_strict_filter.go: validateFilterRoutingInstanceConflictStrict
  // Rejects `then routing-instance X` + `then discard/reject` at commit (strict) / warns (lenient)
  ```
- Trace: Verified fix on 8cd816e35. Before: PBR term with RI+discard built ip rule steering into VRF even though userspace dropped (fail-open VRF leak). After: Go commit gate rejects at strict, lenient warns, and buildPBRFromFilter skips steering (deny wins).
- Refutation: Checked fix, verified on HEAD. ps-review-024 M-01 residual is closed.
- Status: FIXED (#4534) — verified on 8cd816e35, no re-report.

---

### [F-006] NEGATIVE: Single-rate policer unenforced — FIXED #4514 verified

- Title: Single-rate policer silently unenforced — FIXED
- Severity: N/A (fixed)
- Evidence:
  ```rust
  // userspace-dp/src/filter/compiler.rs: single-rate policers lowered into three-color runtime
  // Before #4514: state.policers map never consumed — then policer X was no-op
  // After #4514: build_single_rate_policer_state maps bandwidth/burst → srTCM committed bucket
  ```
- Status: FIXED (#4514) — verified.

---

### [F-007] NEGATIVE: Family any IPv6 arm — FIXED #4287+#4296+#4426 verified

- Title: Family any dual-compile — FIXED
- Severity: N/A
- Evidence:
  ```go
  // pkg/config/compiler_firewall.go: dests = both maps for family any
  // validateFirewallFilterFamilyAnyMatchesAST: rejects single-family matches under any
  // validateFirewallFilterFamilyAnyMatchesAST: rejects single-family prefix-list under any (#4426)
  ```
- Status: FIXED — verified, no new bypass.

---

### [F-008] LOW: is-fragment match on non-first fragment — correct, not a bug

- Title: is-fragment gated correctly — verified not a bug
- Severity: N/A
- Evidence:
  ```rust
  // userspace-dp/src/filter/engine/matching.rs: per_packet_l4_matches
  if term.is_fragment && !extra.is_fragment { return false; }
  // is_fragment is L3-derived, NOT gated by l4_present — correct
  // Non-first fragment still has is_fragment=true (from IP flags), so it matches is-fragment terms
  ```
- Status: NEGATIVE — correct implementation, no bug.

---

## Summary

### New findings: 0 High/Med fail-opens

All HIGH/CRITICAL fail-opens previously reported (PBR reject #4392, PBR discard #4534, single-rate policer #4514, three-color default #4535, family any #4287/#4426, source-prefix-list #3843) are VERIFIED FIXED on 8cd816e35.

### Confirmed residuals (known, low severity):

- F-001: flex_mask==0 → match-all (F-236 known) — Go path safe (pre-masked value, defaults non-zero mask), hand-built snapshot only. Defense-in-depth fix optional.
- F-002: PBR/next-table global ip rule widening — documented limitation, not a live bug. Next-table per-RI gap is F-174 (known).
- F-003: filter_term_semantics_match omits flex_* — moot because flow-cache DECLINE on flex (no cached verdict). Defense-in-depth gap, low priority.

### Verified FIXED (no re-report):

- #4535 three-color policer default — FIXED
- #4534 PBR discard kernel-mirror — FIXED
- #4514 single-rate policer — FIXED
- #4392 PBR reject — FIXED
- #4287/#4426 family any — FIXED
- #3843 source-prefix-list — FIXED

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

### Intentional divergences (NOT bugs):

- PBR no iif (global rule) — documented widening
- Next-table global (main table only) — documented, per-RI is F-174 gap
- Rib-group Phase-1 only into main — documented
- Flex match-start payload rejected at commit — intentional
- DSCP-0 ip rule unrepresentable (dropped) — documented
- Three-color only color-blind+discard — documented
- Intrazone default-permit, host-originated junos-host, IPsec-passthrough-exempt — documented

---

## Suggested issue split: NONE (no new High/Med fail-opens)

All cohort 8 code on 8cd816e35 is in good shape. The 3 confirmed residuals are low/defense-in-depth/documented gaps, not warranting new issues unless triaged as hardening follow-ups.

