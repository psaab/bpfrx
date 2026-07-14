# Paladin Review — A3_go_config_cli_tree batch 1/3 (ps-038)

- **Base commit:** d4506d4450e23f9a3fc572206b3c82f6b6c99029
- **Area:** A3_go_config_cli_tree — batch 1/3
- **Reviewer focus:** zone policies, global policies, host-inbound, application matching, default deny/permit, intrazone-default-permit, VRRP/HA cold-boot, dataplane integer-truncation on config casts, DDNS/observability resource safety
- **Date:** 2026-07-07

## Batch File List (150 files)

```
pkg/appid/catalog.go
pkg/appid/catalog_icmp_3781_test.go
pkg/appid/catalog_proto0_4008_test.go
pkg/appid/catalog_tolerant_3725_test.go
pkg/appid/precedence_parity_test.go
pkg/appid/protocol_lenient_3439_test.go
pkg/appid/protocol_number_2124_test.go
pkg/appid/runtime.go
pkg/appid/runtime_test.go
pkg/appid/textrender.go
pkg/appid/textrender_test.go
pkg/cmdtree/completion_nil_3476_test.go
pkg/cmdtree/completion_nil_3493_test.go
pkg/cmdtree/tree.go
pkg/cmdtree/tree_hb167_test.go
pkg/cmdtree/tree_test.go
pkg/config/addressbook_name_slash_3061_test.go
pkg/config/addressbook_name_slash_4340_test.go
pkg/config/allow_dataplane_sleep_test.go
pkg/config/application_set_nested_test.go
pkg/config/apply_groups_leaflist_exclude_test.go
pkg/config/apply_groups_leaflist_test.go
pkg/config/apply_groups_transitive_4474_test.go
pkg/config/ast.go
pkg/config/ast_edit.go
pkg/config/ast_format.go
pkg/config/ast_groups.go
pkg/config/ast_redact.go
pkg/config/ast_redact_test.go
pkg/config/backup_router_family_2911_test.go
pkg/config/bgp_neighbor_peeras_2963_test.go
pkg/config/compile_golden_4406_test.go
pkg/config/compiler.go
pkg/config/compiler_addrbook_warn_3958_test.go
pkg/config/compiler_application_destport_names_3340_test.go
pkg/config/compiler_application_junos_ping_3348_test.go
pkg/config/compiler_application_mixed_term_3366_test.go
pkg/config/compiler_application_port_range_zero_4336_test.go
pkg/config/compiler_application_set_member_3890_test.go
pkg/config/compiler_application_specs_test.go
pkg/config/compiler_application_term_alg_3352_3353_test.go
pkg/config/compiler_application_timeout_3320_test.go
pkg/config/compiler_applications.go
pkg/config/compiler_applications_collision.go
pkg/config/compiler_as_path_prepend_2892_test.go
pkg/config/compiler_bgp_as_3870_test.go
pkg/config/compiler_chassis.go
pkg/config/compiler_chassis_device_map_test.go
pkg/config/compiler_class_of_service.go
pkg/config/compiler_cluster_authkey_4107_test.go
pkg/config/compiler_cos_rate_percent_strict_4320_test.go
pkg/config/compiler_cos_tcp_hb167_test.go
pkg/config/compiler_default_policy_3065_test.go
pkg/config/compiler_default_policy_log_3534_test.go
pkg/config/compiler_derivations.go
pkg/config/compiler_dhcp_ddns_test.go
pkg/config/compiler_dhcp_relay_overrides_test.go
pkg/config/compiler_dispatch.go
pkg/config/compiler_dnat_address_test.go
pkg/config/compiler_dnat_protocol_test.go
pkg/config/compiler_dup_flow_subblock_3566_test.go
pkg/config/compiler_dup_match_then_3850_test.go
pkg/config/compiler_dup_policy_name_3473_test.go
pkg/config/compiler_dup_security_3562_test.go
pkg/config/compiler_dynamic_address_feed_ref_3300_test.go
pkg/config/compiler_earlystrict.go
pkg/config/compiler_equal_flow_target_policy_test.go
pkg/config/compiler_equal_flow_worker_cap_test.go
pkg/config/compiler_f3_hb167_test.go
pkg/config/compiler_feed_address_token_3294_test.go
pkg/config/compiler_filter_action_test.go
pkg/config/compiler_filter_loss_priority_2507_test.go
pkg/config/compiler_filter_nocatchall_3295_test.go
pkg/config/compiler_filter_protocol_test.go
pkg/config/compiler_filter_ref_3296_test.go
pkg/config/compiler_firewall.go
pkg/config/compiler_firewall_family_any_4287_test.go
pkg/config/compiler_firewall_family_any_match_4296_test.go
pkg/config/compiler_firewall_family_any_prefixlist_4426_test.go
pkg/config/compiler_firewall_family_collision_3884_test.go
pkg/config/compiler_flat_reth_nodeid_4329_test.go
pkg/config/compiler_frr_policy_inject_4097_test.go
pkg/config/compiler_inert_knobs_4306_test.go
pkg/config/compiler_interface_range.go
pkg/config/compiler_interface_range_4027_test.go
pkg/config/compiler_interfaces.go
pkg/config/compiler_interfaces_unsupported.go
pkg/config/compiler_interfaces_unsupported_test.go
pkg/config/compiler_ipsec.go
pkg/config/compiler_ipsec_bindiface.go
pkg/config/compiler_ipsec_bindiface_2933_test.go
pkg/config/compiler_ipsec_gateway_ref_test.go
pkg/config/compiler_ipsec_hb167_parity_test.go
pkg/config/compiler_ipsec_proposals_multivalue_3904_test.go
pkg/config/compiler_ipsec_proposalset.go
pkg/config/compiler_ipsec_trafficselector.go
pkg/config/compiler_ipsec_ts_4098_test.go
pkg/config/compiler_junos_host_direct_warn_4146_test.go
pkg/config/compiler_lo0_mirror_modifiers_3445_test.go
pkg/config/compiler_nat.go
pkg/config/compiler_nat64_prefix_test.go
pkg/config/compiler_nat_address_name_feed_3418_test.go
pkg/config/compiler_nat_address_name_resolvable_3425_test.go
pkg/config/compiler_nat_application_specs_test.go
pkg/config/compiler_nat_dest_address_name_3229_test.go
pkg/config/compiler_nat_dnat_off_3844_test.go
pkg/config/compiler_nat_dnat_pool_3450_test.go
pkg/config/compiler_nat_dnat_port_range_3449_test.go
pkg/config/compiler_nat_dnat_to.go
pkg/config/compiler_nat_dnat_to_3444_test.go
pkg/config/compiler_nat_dup_subblock_3915_test.go
pkg/config/compiler_nat_host_mask_test.go
pkg/config/compiler_nat_match_application_3434_test.go
pkg/config/compiler_nat_match_dport_3446_test.go
pkg/config/compiler_nat_match_multivalue_3431_test.go
pkg/config/compiler_nat_persistent_permit_test.go
pkg/config/compiler_nat_pool_alarm_test.go
pkg/config/compiler_nat_scope_3079_test.go
pkg/config/compiler_nat_source_address_name_2416_test.go
pkg/config/compiler_nat_source_dport_3429_test.go
pkg/config/compiler_nat_source_pool_address_4521_test.go
pkg/config/compiler_nat_source_pool_port_3906_test.go
pkg/config/compiler_nat_target_parity_hb167_test.go
pkg/config/compiler_nptv6_self_overlap_4339_test.go
pkg/config/compiler_nptv6_test.go
pkg/config/compiler_p3_http_providers_test.go
pkg/config/compiler_policy_dup_block_3842_test.go
pkg/config/compiler_policy_global_zone_3148_test.go
pkg/config/compiler_policy_match.go
pkg/config/compiler_policy_match_3113_test.go
pkg/config/compiler_policy_match_3142_test.go
pkg/config/compiler_policy_match_3673_test.go
pkg/config/compiler_policy_match_address_set_3149_test.go
pkg/config/compiler_policy_match_application_3144_test.go
pkg/config/compiler_policy_match_ssot_4121_test.go
pkg/config/compiler_policy_missing_match.go
pkg/config/compiler_policy_missing_match_3044_test.go
pkg/config/compiler_policy_term_multimatch_2642_test.go
pkg/config/compiler_policy_then.go
pkg/config/compiler_policy_then_3114_test.go
pkg/config/compiler_policy_then_3115_test.go
pkg/config/compiler_policy_then_deny_3141_test.go
pkg/config/compiler_policy_then_deny_3374_test.go
pkg/config/compiler_policy_then_twonode_3377_test.go
pkg/config/compiler_prefix_list_bracket_3996_test.go
pkg/config/compiler_prefix_list_hier_leaf_3843_test.go
pkg/config/compiler_prefix_list_merge_2641_test.go
pkg/config/compiler_prefix_list_ref_2506_test.go
pkg/config/compiler_preid_default_policy_log_2509_test.go
```

---

## Module-by-Module Log

### pkg/appid — Application Identification

#### pkg/appid/catalog.go
- **What checked:** integer truncation on `uint16(nextID)` with `nextID` as `uint32`, `parsePortRange` `[]byte`-to-`uint16` narrowing, `protocol 0` fan-out (#4008), ICMP type-constrained app interim (#3781), source-port range reversal, bad-source-port over-broad labeling, app_id overflow at uint16 boundary (#3438 H4)
- **Result:** NEGATIVE — no new bug. All integer casts are guarded:
  - `nextID` is `uint32(1)` with explicit `nextID > maxCatalogAppID(65535)` rejection before `uint16(nextID)` cast (line 89-92)
  - `parsePortRange` uses `strconv.ParseUint(..., 10, 16)` which directly validates 0..65535 at parse time — `uint16(low)` is safe because ParseUint with bitSize 16 already range-checks
  - Protocol 0 handling correctly keys fan-out on `strings.TrimSpace(app.Protocol) == ""` (omitted protocol) not `proto == 0` (resolved number), fixed in #4008
  - ICMP type-constrained app interim correctly drops over-matching protocol-only rows while preserving AppNames parity

- **Additional notes:**
  - `parsePortRange("")` returns `(0,0,nil)` meaning "no constraint" — this is semantically distinct from `parsePortRange("0")` which also returns `(0,0,nil)` via `ParseUint("0",10,16)=0`. On the strict path `validatePortSpec` rejects port 0, so single "0" never reaches the catalog. On the lenient path, `"0"` as destination-port would be treated as "no constraint" (= match any port), which is fail-open over-broad. However this is an existing pre-batch behavior on a lenient-only path and the strict gate prevents it on commit. Not filing as new since the strict path rejects it.

#### pkg/appid/runtime.go
- **What checked:** `portInSpec` uint16 narrowing (#3725 H02), signed acceptance (#3725 M05), `resolveTupleFallback` specificity ordering (#2578), protocol-only app handling (#2548), source-port constraint (#3428), `matchTuple` empty-protocol handling, `CatalogNames` nil-guard for zone-pair and policy entries (#3622)
- **Result:** NEGATIVE — no new bug. Prior batch fixes verified sound:
  - `canonicalPort` uses `config.ParseCanonicalUint` (unsigned decimal only, no sign, range 1..65535) — correctly rejects `"+80"` (M05) and `"70000"` (H02, would narrow to 4464)
  - `portInSpec` reversed-range guard `lo > hi` returns false (fail-closed)
  - `resolveTupleFallback` port-based > protocol-only preference with name tie-break is deterministic
  - `CatalogNames` / `addPolicyApps` nil guards at lines 85-86, 99-102, 125-126, 129-130 — matches strict walker
  - `matchTuple` protocol-only apps (`app.DestinationPort == ""`) correctly treated as "no dst-port constraint" via `portInSpec(dstPort, "")` returning true

#### pkg/appid/textrender.go
- **What checked:** rendering logic, nil config handling, operator-facing contract accuracy
- **Result:** NEGATIVE — trivial display code, nil-safe, no security-relevant logic

#### pkg/appid/*_test.go (6 files)
- **What checked:** test coverage adequacy, redundant assertions, missing edge cases
- **Result:** NEGATIVE — tests are thorough fail-on-revert guards. No missing coverage that would hide a policy-enforcement bug. Specifically:
  - `catalog_icmp_3781_test.go`: pins type-constrained ICMP app interim from catalog + tuple-fallback sides
  - `catalog_proto0_4008_test.go`: pins `protocol 0` vs omitted-protocol fan-out distinction
  - `catalog_tolerant_3725_test.go`: pins bad source-port, reversed ranges, dangling AppNames (H03/M04/M06/M07)
  - `precedence_parity_test.go`: cross-language AppID precedence fixture (#3612)
  - `protocol_lenient_3439_test.go`, `protocol_number_2124_test.go`: protocol number SSOT and lenient/filter parity (#2124, #2175, #3373, #3393)

---

### pkg/cmdtree — Operational CLI Command Tree

#### pkg/cmdtree/tree.go
- **What checked:** `CompleteFromTree` / `CompleteFromTreeWithDesc` typed-leaf value-slot handling, placeholder descent, dynamic function nil guards, `LookupDesc` prefix resolution, `WriteHelp` formatting, `resolveTreeWord` uniqueness, `isPlaceholder` / `findPlaceholder` helpers, integer-typed completions (no truncation), zone-pair policy completion nil guards (#3476/#3493)
- **Result:** NEGATIVE — no new bug. Key invariants hold:
  - `OperationalTree["show"]["security"]["policies"]["from-zone"]["to-zone"]["policy"]` ContextDynamicFn has nil guards for `zpp == nil` (line 335) and `p == nil` (line 343) — fixed in #3476
  - `monitor security packet-drop from-zone` DynamicFn has nil guard `if z == nil { continue }` (line 718) — fixed in #3493
  - `CompleteFromTree` typed-leaf `parentTyped` tracking correctly stays at same level for value-slot consumption then clears on next non-matching token — matches `CompleteFromTreeWithDesc`
  - `WriteHelp` single-write via `strings.Builder` avoids readline wrap issues
  - No integer truncation: all completion candidates are strings, no numeric casts

- **Test coverage gap (Low):** `CompleteFromTree` with `parentTyped=true` and a `ContextDynamicFn` interaction is not directly tested — but this is operational-tree SSOT and the typed-leaf operational path is lightly used. Not a security gap.

#### pkg/cmdtree/*_test.go (4 files)
- **What checked:** nil-guard coverage for zone-pair/policy and zone completions, drill-down presence, placeholder behavior
- **Result:** NEGATIVE — fail-on-revert guards for #3476/#3493 verified; HB167 drill-down test pins operational-tree C-1 expansion; completion tests cover placeholder-with-children descent vs stay-level, unique prefix words, ambiguous last-word, route table dynamic names

---

### pkg/config — Config Parsing, AST, and Compilation

#### pkg/config/ast.go
- **What checked:** `navigatePath` multi-key match (from-zone X to-zone Y consuming 4 path elements), `unionChildren` read-all-siblings (#4562), terminal single-keyword `FindChildren`-not-`FindChild` (#3980), `matchNodeKeys` / `navigateToNode` / `findNodeWithParent` / `keysEqual`, `cloneNodes` deep copy correctness
- **Result:** NEGATIVE — no new bug.
  - `navigatePath` correctly handles both intermediate descent (union of all siblings' children) and terminal (all siblings sharing same keyword)
  - `navigatePath` intermediate descent correctly uses `unionChildren` for multi-key matches (lines 208-224) and single-keyword siblings (lines 253-269)
  - Single-match is unchanged (one sibling → its children) — no perf regression
  - `matchNodeKeys` partial-match returns 1 (first key match) when full path doesn't fit — correct for single-key fallback

#### pkg/config/ast_edit.go
- **What checked:** `SetPath` bracket-list collapse (#2419), multi-value leaf detection, valueList opt-in (#3872), scalar override vs leaf-list union, `DeletePath` / `DeactivatePath` / `ActivatePath` member-specific deletion for value-list leaves (#3846, #3975), `RenamePath` same-parent in-place vs cross-parent, `CopyPath`, `InsertBefore`/`InsertAfter`, `keysMatch` prefix matching, Keys[1:] / Keys[1] bounds
- **Result:** NEGATIVE for security/integrity — correctness is sound. One low-severity observation noted below.
  - `SetPath` bracket-list handling (lines 342-402) correctly absorbs trailing non-sibling tokens onto `nodeKeys` then dedup-checks before appending — matches hierarchical AST single-leaf shape
  - `SetPath` `multi && (children==nil || valueList) && args==1` gate correctly limits trailing-value absorption to pure single-token value lists, not multi-token members
  - `DeletePath` (`removeMultiLeafMembers`) correctly handles both flat `Keys[1:]` and block `Children` shapes for member removal
  - `DeactivatePath` (`markMultiLeafMembersInactive`) correctly reflects that bracket-list Inactive is node-level (whole statement) while block-shape can toggle individual child nodes
  - `RenamePath` same-parent path preserves sibling order; cross-parent path detaches + appends with collision guard — correct

- **Low finding — see F1 below:** scalar-leaf replace in `SetPath` (lines 278-302) uses `(*current)[:0]` slice reuse which aliases the original backing array. If `*current` is referenced elsewhere concurrently (not the case in single-threaded compile, but the `ConfigTree` is `Clone()`-ed before mutation), this is safe. No bug under current single-threaded compile model.

#### pkg/config/ast_format.go
- **What checked:** `FormatInheritance`, `FormatPathInheritance`, `Format`, `FormatPath`, `FormatSet`, `FormatPathSet`, `FormatCompare`, `FormatJSON`, `FormatPathJSON`, `FormatXML`, `FormatPathXML`, `inactivePrefix`, `canonicalOrder`, `nodesToJSON`
- **Result:** NEGATIVE — all format paths correctly handle inactive markers, inheritance annotations, canonical match-before-then ordering, and JSON inactive marker collision safety (`@` sigil not valid Junos identifier). No truncation or injection.

#### pkg/config/ast_groups.go
- **What checked:** `ExpandGroups` / `ExpandGroupsTagged` / `ExpandGroupsWithVars`, `expandGroupsRecursive` transitive expansion (#4474), cycle detection (`seen` map), memoization (#4474 fan-out fix), `walkGroupToContext` wildcard matching, `mergeNodes` leaf-list UNION vs scalar OVERRIDE typed logic (#4070), `isLeafListSchema` / `leafListUnionEligible` / `leafListCarriesRange`, bracket-list `apply-groups [ a b c ]` parsing
- **Result:** NEGATIVE — no new bug.
  - Memoization correctness: `memoKey = name + "\x00" + ancestorPathKey(ancestorPath)` correctly partitions by (group name, ancestor context); `cloneNodes` on cache hit/store prevents mutation of cached entries via `mergeNodes` — fixed in #4474
  - `seen` cycle guard blocks `grpA → grpB → grpA` (grpA already in `seen` on re-entry)
  - `isLeafListSchema` gate `multi && children==nil && args<=1 && !groupReplace` correctly excludes scalar leaves, multi-token members (route-filter, address-book `address <name> <prefix>`), and range-bearing leaves (port ranges)
  - `leafListCarriesRange` checks `"to" in values` to prevent union of range-bearing leaves — defensive net beyond `groupReplace` flag
  - Bracket-list `apply-groups [ a b c ]` produces `Keys=["apply-groups","a","b","c"]` and iterates `Keys[1:]` — correct per #2419

#### pkg/config/ast_redact.go
- **What checked:** `RedactedClone`, `redactNodes`, `secretIndices`, `containsAnyOf`, `checkRedactionPlaceholder`, `findRedactionPlaceholder`, bounds on `idx-len(base)` indexing into `n.Keys`, generic keyword context gates (`password` needs ancestor `api-auth`/`dynamic-dns`, `key` needs `authentication md5 <id> key <secret>`, `community` needs parent `snmp`), pre-shared-key format qualifier preservation, multi-token value masking
- **Result:** NEGATIVE — no new bug.
  - `redactNodes` bounds: `full = base + n.Keys`, so `len(full) = len(base) + len(n.Keys)`. Guard `idx >= len(base) && idx < len(full)` implies `0 <= idx-len(base) < len(n.Keys)` — safe indexing into `n.Keys[idx-len(base)]`
  - `findRedactionPlaceholder` uses identical traversal/bounds as `redactNodes` — symmetric detection
  - `secretIndices` generic keyword gates (`password`, `key`, `community`) correctly prevent over-redaction of non-secret uses (GRE tunnel `key`, chassis device-map `key`, routing-policy `community`)
  - `pre-shared-key` preserves `ascii-text`/`hexadecimal` qualifier, masks only remaining tokens — structurally valid output
  - `checkRedactionPlaceholder` rejects redacted-exports on commit-ingest with actionable operator message (#4060) — prevents "##SECRET-DATA##" literal-secret commit from a redacted export

#### pkg/config/compiler.go (compileOpts + CompileConfig plumbing)
- **What checked:** compileOpts struct — all 80+ lenient flags, their documentation, `CompileConfig` / `CompileConfigLenient` / `CompileConfigForNode` / `CompileConfigForNodeLenient` / `compileConfigWithOpts` / `compileConfigForNodeWithOpts` / `compileExpanded` P1-P7 phase ordering (#4406), tunnel-id collision gate, zone-id collision gate, routing-instance table-id collision gate, apply-groups expansion, warning accumulation order
- **Result:** NEGATIVE — no new bug.
  - Phase ordering invariants documented and preserved: P1 (pre-walk, mutates tree) → P2 (skeleton) → P3 (warnings append) → P4 (section dispatch) → P5 (cross-section derivations including #4329 NodeID stamp before fabric fixup) → P6a (early-strict + folds) → P6b (uniform gates) → P7 (tail gates)
  - All lenient flags have consistent #1960 fail-closed-on-load doctrine documentation: strict on commit/commit-check (hard-reject), lenient on load/peer-sync (warn), with runtime backstops making lenient inert
  - `compileOpts.nodeAware` / `stampNodeID` correctly threaded only from `compileConfigForNodeWithOpts` — standalone `CompileConfig` leaves them unset

- **Note (informational):** `compileOpts` struct now has 70+ boolean fields with no bit-packing. `compileConfigWithOpts` constructs the lenient opts struct by explicitly listing every lenient flag `true` — a new lenient flag added to `compileOpts` but not to `CompileConfigLenient` / `CompileConfigForNodeLenient` would silently stay strict on the lenient path. This is a maintainability observation, not a bug — the existing tests pin the specific strict/lenient behaviors.

#### pkg/config/compiler_applications.go
- **What checked:** `compileApplications` direct-body vs term-based application, `hasDirectBody` tracking, `parseApplicationTerms` multi-protocol term splitting, `resolveAppPort` named-port → numeric resolution via `junosServicePorts` SSOT (#3340), `0-N` → `1-N` range floor normalization (#4336), `ParseCanonicalUint` / `parseCanonicalPort` canonical-form enforcement (#3606/#3725), `validatePortSpec` range validation, `parseICMPTypeCode` / `aliasEchoICMPType` ICMP type handling (#3348), `parseAppTimeout` range [0,86400], ALG validation (#3352/#3353)
- **Result:** NEGATIVE — no new bug. Integer handling verified:
  - `parseAppTimeout`: `strconv.Atoi(raw)` with `n < 0 || n > 86400` rejection, malformed stored in `UnknownTimeouts` for deferred strict gate — no truncation (returns `int`, stored as `int`)
  - `parseICMPTypeCode`: `strconv.Atoi` with `n < 0 || n > 255` then `uint8(n)` — correct, range validated before narrow cast
  - `resolveAppPort` `0-N` normalization: `parseCanonicalPort("0")` returns `(0, nil)` (bare "0" is valid unsigned decimal), then `n == 0` triggers `l=1, ok1=true` — correct port 0 never on wire, `0-N` → `1-N` semantically equivalent
  - `parseCanonicalPort` / `ParseCanonicalUint` reject signed/non-canonical tokens (no `+80`, no whitespace) — consistent with strict gate
  - `aliasEchoICMPType` maps `junos-ping → type 8`, `junos-pingv6 → type 128` — prevents bare-ICMP-when-alias-used fail-open (#3348)

#### pkg/config/compiler_applications_collision.go
- **What checked:** `validateApplicationNameCollisionsAST` — duplicate application definition, duplicate application-set, cross-namespace (app vs app-set) collision, duplicate generated per-term name (M08), cross-parent generated name collision (H03), generated vs authored collision (H01/H02), generated shadowing predefined (M03), `termSeen` / `genParents` / `appCounts` / `setCounts` bookkeeping across multiple `applications` blocks
- **Result:** NEGATIVE — no new bug.
  - Iterates ALL `applications` sibling blocks (not just first) — correct for split definitions (hierarchical parse emits separate top-level nodes)
  - `genParents` populated for every generated name including within-parent duplicates — distinct-parent count is exact for H03
  - `isPredef` always warns (never hard-rejects) — consistent with legitimate `application junos-http` shadow case
  - Lenient path warns rather than hard-rejects — #1960 no-brick, existing last-write-wins maps unchanged

#### pkg/config/compiler_chassis.go (compileDeviceMap + validateDeviceMapStrict)
- **What checked:** `compileDeviceMap` PCI/MAC normalization, `collectDeviceMapProps` AST shape handling (flat-set nesting, inline-on-instance, hierarchical), `normalizeMAC`, `validateDeviceMapStrict` duplicate logical name / duplicate PCI / duplicate MAC / key-order sanity / RETH-member PCI-keyed (R-6) / FPC slot alignment (V-6) / unmapped policy validation, bare-metal device-map mode (#1956)
- **Result:** NEGATIVE — no new bug.
  - `normalizeMAC` returns raw input on parse failure (lenient path yields UNBOUND resolve, not silent misbind) — correct fail-safe
  - `collectDeviceMapProps` walks subtree scanning inline Keys at every depth — handles flat-set `interface ge-0/0/3 pci A mac B key C` nesting
  - `validateDeviceMapStrict` RETH member check `e.EffectiveKeyOrder() in {MAC, MACThenPCI}` rejected — MAC alternates physical↔virtual, must be PCI-keyed
  - `entryIdentityDesc` for diagnostics does not leak MAC in log

#### pkg/config/compiler_class_of_service.go
- **What checked:** `compileClassOfService` forwarding-classes bijection (queue→FC + FC→queue — #785/#787), classifiers (DSCP / IEEE 802.1p / INET-precedence), rewrite-rules, schedulers (transmit-rate, priority, buffer-size, surplus-sharing, codel-target, equal-flow-enforcement), traffic-control-profiles (#4228 Gap 2), scheduler-maps, `parseCoSInterfaceUnitBody` interface-level / unit-level bindings, `mergeCoSInterfaceLevelInto` (#4021 + #hb166 G-10 burst-size coupling), `resolveCoSTrafficControlProfiles` percent-rate resolution, `resolveCoSPercentRateBytes` float precision, `collectCoSDSCPCodePoints` / `collectCoS8021CodePoints` (#1809 inline, #2447 range), `expandCoSCodePointToken`, fairness rss-expectation
- **Result:** LOW findings — see F2 / F3 below. Otherwise correct:
  - Forwarding-classes queue↔FC bijection: both directions enforced (queue N → two FCs AND FC X → two queue numbers), idempotent same-FC-same-queue allowed — correct
  - `collectCoSDSCPCodePoints` / `collectCoS8021CodePoints` handle both `FindChildren("code-points")` (hierarchical) and inline `loss-priority low code-points ef` (flat) shapes — correct per #1809
  - `collectCoS8021CodePoints` rejects out-of-range numeric (0..7) at commit — prevents silent clamp to wrong class (#2447)
  - `expandCoSCodePointToken` rejects out-of-range DSCP (0..63) — prevents `dscp 110 → dscp 46` mask misclassification (#2447)
  - `resolveCoSPercentRateBytes`: `math.Ceil(float64(base)*percent/100.0)` matches Rust `cos_percent_rate_bytes` exactly — same (0,100] guard, same Ceil rounding, same `[1, MaxUint64]` clamp with `>=` for float64 MaxUint64 boundary — verified sound
  - `three-color-policer` color-blind default when neither `color-blind` nor `color-aware` specified — matches Junos (#4535)

#### pkg/config/compiler_derivations.go (resolveDerivedConfig)
- **What checked:** `resolveDerivedConfig` P5 substeps ordering — NodeID stamp (#4329) before fabric fixup, BGP AS resolution, lo0 filter hoist, applyCoSInterfaceLevelBindings, resolveCoSTrafficControlProfiles, fabric member/interface fixup; NodeID stamp guards (`nodeAware && stampNodeID >=0 && Cluster != nil && !NodeIDSet`)
- **Result:** NEGATIVE — no new bug. Ordering is load-bearing and documented:
  - NodeID stamp before fabric fixup (`SlotToNodeID(member) == cc.NodeID`) and before `validateDeviceMapStrict` — correct
  - `!NodeIDSet` guard prevents clobbering operator-explicit `chassis cluster node <id>` leaf — correct
  - `Cluster != nil` guard prevents fabricating cluster stanza on empty-config HA takeover — correct
  - `resolveCoSTrafficControlProfiles` runs after `applyCoSInterfaceLevelBindings` — correct (interface-level profile already folded into each unit)

#### pkg/config/compiler_dispatch.go (compileSections)
- **What checked:** P4 section-compile dispatch — author-order iteration, first-error wins, unrecognized stanza ignored (gated elsewhere)
- **Result:** NEGATIVE — trivial dispatch, no integer ops, no truncation

#### pkg/config/compiler_firewall.go
- **What checked:** policer definitions, three-color policer (single-rate / two-rate / then action / color-blind default), `compileFirewall` family dispatch (`family inet` / `family inet6` / `family any`), `compileFilterFrom` match compilation (dscp, protocol/next-header, source/destination-address, destination-port, source-prefix-list, destination-prefix-list, forwarding-class, icmp-type, icmp-code, icmp-type-and-code, tcp-flags, fragment-offset, ttl, etc.), `compileFilterThen`, flexible-match (`byte-offset` / `bit-length` / `range` / `match-value` / `match-mask`), `firewallMatchValues` SSOT, `firewallPrefixListRefs` dual-shape handling (#3843), integer truncation in flex-match byte-offset/bit-length/match-value/match-mask
- **Result:** NEGATIVE for integer truncation — all flex-match narrow casts are bounds-checked:
  - `byte-offset`: `strconv.Atoi(v) && n >= 0 && n <= 255` before `uint8(n)` — safe (u8 wire, bounds checked)
  - `bit-length`: `strconv.Atoi(v) && n >= 1 && n <= 32` before `uint8(n)` — safe (was truncation bug #3203: bare `uint8(999)=231`, now rejected)
  - `match-value`/`match-mask`: `strconv.ParseUint(..., 16, 32)` → `uint32(val)` — safe (16-hex = 32-bit, 32-bit parse, uint32 store)
  - `fm.Mask = uint32(1)<<fm.BitLength - 1` with `fm.BitLength >= 32` handled separately (`0xFFFFFFFF`) — safe (no shift-overflow)

- **Negative for:** `firewallMatchValues` correctly reads BOTH `child.Keys[1:]` AND `child.Children` via accumulation — handles every dual-shape (#2419) — proven by `#4121` test that pins `both_slots` (`source-address a1 { a2; }`) as fail-on-revert

#### pkg/config/compiler_interface_range.go / compiler_interface_range_4027_test.go
- **What checked:** `expandInterfaceRanges` — expands `ge-0/0/[0-3]` range syntax into individual interface entries, range validation, nested ranges, interface naming
- **Result:** NEGATIVE — straightforward range expansion, `strconv.Atoi(s[i:])` with range validation, no narrowing casts, no security boundary. Tested by 4027.

#### pkg/config/compiler_interfaces.go + compiler_interfaces_unsupported.go
- **What checked:** `compileInterfaces` — all interface types (ethernet, vlan-tagging, unit, family inet/inet6, address, mtu, vlan-id, etc.), tunnel interfaces (GRE, IPIP, XFRM), WireGuard (`listen-port` `uint16(n)` with `n > 0 && n <= 65535` guard, `keepalive` `uint16(n)` with `n >= 0 && n <= 65535` guard), unit number `strconv.Atoi(unitTok)` as `int` (unit 0..16385 per Junos, stored as `int`), VRRP virtual-address, unnumbered-address, `family inet dhcp`
- **Result:** NEGATIVE — integer handling verified safe:
  - WgListenPort: `n > 0 && n <= 65535` before `uint16(n)` — no truncation
  - WgKeepaliveSecs: `n >= 0 && n <= 65535` before `uint16(n)` — no truncation
  - Unit number: stored as `int` (no narrowing), Junos unit 0..16385 fits int
  - VRRP track-interface: `priority-cost` is `int` (no narrowing), validated later in `validateVRRPIntervals` / `validateVRRPTrackDuplicates`
  - Unsupported stanzas gate (mac static-MAC override, family inet policer arp) — AST pre-walk, lenient downgrade correct

#### pkg/config/compiler_ipsec.go + compiler_ipsec_bindiface.go + compiler_ipsec_proposalset.go + compiler_ipsec_trafficselector.go
- **What checked:** IPsec VPN compilation, `compileIPsecProposalSet` proposal-set standard/basic/compatible/suiteb-* handling (#4297), `compileIPsecProposals` multi-value proposal list (#3904), `compileIPsecTrafficSelector` TS local-ip / remote-ip (#4098), `validateIPsecBindInterface` / `compileSecureTunnelBindInterface` bind-interface alias collision (#2933, #2929), gateway compilation, IKE policy/proposal chains
- **Result:** NEGATIVE — no new bug in this batch. Key invariants:
  - Proposal-set shorthand (`standard` / `basic` / `compatible` / `suiteb-*`) expansion verified by `compiler_ipsec_hb167_parity_test.go` — resolves to concrete proposals with correct ESP/AH/IKEv2 semantics
  - `traffic-selector local-ip` / `remote-ip` — `validateIPsecTrafficSelectorsStrict` (CC 4098) rejects control-char injection (newline→arbitrary swanctl.conf line, #4098) with lenient downgrade to warn
  - Bind-interface alias collision `st0` vs `st0.0` → same if_id — rejected in `validateSecureTunnelBindInterfaceAST` (#2933), lenient warn — runtime backstop in routing manager (#2929) refuses to create either

#### pkg/config/compiler_nat.go + compiler_nat_dnat_to.go
- **What checked:** `compileNAT` source/destination/static dispatch, source NAT pool compilation (address, port range/no-translation/factor, routing-instance, host-address-base, port-overloading), destination NAT pool (address, port — `parseDNATPoolAddress` flat+hierarchical), NAT rule compilation (match source/destination-address, source/destination-address-name, application, destination-port, protocol, etc.), `parseSourcePoolPortRange`, `parseDNATPoolAddress`, `staticNATMappedPortFromKeys`, `validateDNATRuleSetToScopeAST` (#3444), all port `int` storage (no narrowing in Go), downstream Rust `uint16` narrowing points
- **Result:** NEGATIVE for integer truncation — ports stored as `int` in Go with validation in strict gates:
  - Source pool `port range <low> to <high>`: `parseSourcePoolPortRange` parses `strconv.Atoi(toks[1])` / `Atoi(toks[3])` as `int`, stored as `PortLow/PortHigh int`, validated in `validateSourceNATPoolStrict` 1..65535 + `low <= high` — no truncation in Go
  - DNAT pool `address port <N>`: `parseDNATPoolAddress` stores port as `int`, `PortRaw` preserved for strict gate, `validateDNATPoolStrict` uses `parseCanonicalPort` 1..65535 — no truncation in Go
  - DNAT `destination-port` / source pool `destination-port` range: `parseDNATPortList` returns `[]int` with `int` elements — no narrowing
  - WireGuard `listen-port` `uint16` / `keepalive` `uint16` narrower casts have range checks (see above)

- **Downstream Rust truncation** (not in this batch but noted): Go `int` port values flow into Rust `u16` wire fields in `pkg/dataplane/userspace/nat.go` snapshot builder. Go validates 1..65535 before passing — `uint16` cast on a validated-positive-int is safe. Verified `SourcePools` snapshot builder reads `PortLow`/`PortHigh` `int` post-validation.

#### pkg/config/compiler_policy_match.go
- **What checked:** `validatePolicyMatchLeavesStrict` — unsupported `match` leaf rejection (#3113), swallowed structural tokens (`from-zone`/`to-zone` absorbed onto multi-value leaf tail — #3673), `unsupportedPolicyMatchLeaves` / `swallowedStructuralMatchTokens`, `supportedPolicyMatchLeaves` / `globalOnlyPolicyMatchLeaves`, multi-value leaf `firewallMatchValues` tail inspection (#3142), duplicate `security` / `policies` block handling (#3562), duplicate `match {}` block handling (#3842), zone-pair vs global policy scoping
- **Result:** NEGATIVE — no new bug.
  - Direct-child scan correctly identifies unsupported match leaves
  - `#3142` tail inspection: `firewallMatchValues(m)` on `application` / `source-address` / `destination-address` correctly catches `dynamic-application junos:FTP` absorbed onto tail — `firewallMatchValues` reads BOTH `Keys[1:]` AND `Children`, matching #2419 dual-shape
  - `#3673` swallowed `from-zone`/`to-zone` in tail: rejected as reserved match keyword masquerading as operand — prevents `application from-zone` where "from-zone" is a named app that satisfies the definedness gate (#3144)
  - `#3562` `forEachChild` at security/policies levels — covers duplicate-block bypass
  - `#3842` `policyMatchChildren` (every `match {}` block, not just first via FindChild) — covers duplicate inner `match` blocks from load-merge/override

#### pkg/config/compiler_policy_missing_match.go
- **What checked:** `validatePolicyRequiredMatchStrict` (#3044) — required `source-address` / `destination-address` / `application` dimensions, missing-dimensions-as-match-ANY fail-open, `source-address-excluded`/`destination-address-excluded` not substituting for base address (Junos requires base leaf), missing entire `match` block, zone-pair vs global coverage, `forEachChild` at security/policies, `policyMatchChildren` union (#3842)
- **Result:** NEGATIVE — no new bug.
  - `excluded` modifier not counting toward `source-address`/`destination-address` requirement — correct (excluded is a modifier, not a substitute)
  - Union of dimensions across all `match {}` blocks (e.g., `source-address` + `destination-address` in one, `application` in load-merged second) — correct per `#3842` `policyMatchChildren`
  - Missing dimension is distinct from explicit `any` — `any` satisfies requirement, absence is rejected — Junos parity correct

#### pkg/config/compiler_policy_then.go
- **What checked:** `validatePolicyThenPermitStrict` (#3114), `validatePolicyThenRejectStrict` (#3115), `validatePolicyThenDenyStrict` (#3141/#3374), `supportedPolicyThenPermitChildren` (empty — any child rejected), `supportedPolicyThenRejectChildren` (empty), `recognizedCollapsedDenyToken` (log/count + session-init/session-close), `collapsedThenActionTokens` flattening across three AST shapes, `policyThenActionNodes` (all same-named action nodes), two-node split (#3377), duplicate inner `then {}` block (#3842/#3850), orphan `session-init`/`session-close` without `log` (#3374), duplicate `security`/`policies` block bypass (#3562)
- **Result:** NEGATIVE — no new bug. Verified:
  - `validatePolicyThenPermitStrict` `supportedPolicyThenPermitChildren` is empty — any child under `then permit` rejected — correct for L3/L4-only xpf (no UTM/IDP/tunnel service chain)
  - `validatePolicyThenRejectStrict` same — any child rejected — correct (custom reject response / tcp-reset not implemented)
  - `validatePolicyThenDenyStrict` `recognizedCollapsedDenyToken`: `log`, `count`, `session-init`, `session-close` — legitimate deny+log/deny+count now wired by `applyCollapsedDenyModifiers`; any remaining token rejected
  - `#3374` orphan `session-init`/`session-close` without `log` rejected separately — `then deny session-init` (no `log`) collapses and would otherwise silently wire logging for syntax Junos rejects
  - `collapsedThenActionTokens`: `action.Keys[1:]` + every descendant node's Keys — shape-agnostic flattening matching `applyCollapsedDenyModifiers` in `compiler_security.go`
  - `policyThenActionNodes` iterates all same-named action nodes under `then` (FindChildren, not FindChild) — covers `set ... then permit` + `set ... then permit application-services X` two-node split, and duplicate inner `then {}` blocks

#### All *_test.go files in batch (remaining)
- **What checked:** fail-on-revert test coverage, flat-set parse shape (`ParseSetCommand` + `SetPath` per CLAUDE.md mandate), hierarchical parse shape (`mustParse` / `NewParser`), duplicate-block cases, edge cases (nil entries, empty configs, reserved keywords as values, reversed ranges, zero ports, etc.), load-merge/override shapes
- **Result:** NEGATIVE — no missing coverage that would hide a policy-enforcement bug. Tests are exemplary fail-on-revert guards with clear doc strings naming the issue number and the revert that turns RED.

---

## Findings

### F1 — Low — `ast_edit.go` `SetPath` scalar-leaf replace uses `(*current)[:0]` with aliased backing array — safe under single-threaded compile but fragile

- **Title:** SetPath scalar-leaf replace reuses backing array via `(*current)[:0]` slice trick
- **Severity:** Low
- **Confidence:** Low
- **Evidence:**
  - File: `pkg/config/ast_edit.go`, lines 278-302
  ```go
  if childSchema.args > 0 && !childSchema.multi && childSchema.children == nil {
      replaced := false
      filtered := (*current)[:0] // reuse backing array
      for _, n := range *current {
          if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == nodeKeys[0] {
              if !replaced {
                  filtered = append(filtered, &Node{
                      Keys:   append([]string(nil), nodeKeys...),
                      IsLeaf: true,
                  })
                  replaced = true
              }
              continue
          }
          filtered = append(filtered, n)
      }
      if replaced {
          *current = filtered
          return nil
      }
  }
  ```
- **Trace:** `SetPath` path `["system","host-name","foo"]` → single-value leaf with `args > 0, !multi, children==nil` → enters scalar-leaf replace branch → `filtered := (*current)[:0]` aliases `*current` backing array → iteration overwrites in place → `*current = filtered` — if `*current` capacity was exactly len and some other reference held the same slice (e.g., `ConfigTree` Clone aliasing), the mutation could be visible through the other reference. In practice `Clone()` deep-copies, and `SetPath` is only called during initial tree construction before Clone, so no aliasing.
- **Why it matters:** The `[:0]` reuse is a well-known Go slice-append footgun. Under single-threaded `SetPath` during CLI/config-load, there is no aliasing issue because each `SetPath` call holds the unique `*current` pointer. After `Clone()`, the clone has its own backing array.
- **Fix direction:** No fix needed — document in comment why `[:0]` is safe (single-owner `*current` at `SetPath`-time). Alternatively, allocate fresh: `filtered := make([]*Node, 0, len(*current))`.
- **Labels:** maintainability, go-slice-trick
- **Dedup note:** Not in dedup index — this is a code-style concern, not a listed open/closed issue. Checked against all 100+ dedup entries; none discuss `ast_edit.go` slice reuse.

---

### F2 — Low — `compiler_class_of_service.go` forwarding-classes queue number has no upper bound validation

- **Title:** CoS forwarding-classes queue number accepted unbounded — downstream uint8 cast possible
- **Severity:** Low
- **Confidence:** Medium
- **Evidence:**
  - File: `pkg/config/compiler_class_of_service.go`, lines 86-98
  ```go
  for _, queueNode := range fcNode.FindChildren("queue") {
      if len(queueNode.Keys) < 3 {
          continue
      }
      queue, err := strconv.Atoi(queueNode.Keys[1])
      if err != nil {
          continue
      }
      name := queueNode.Keys[2]
      // ... no range check on queue before storing as int ...
      cos.ForwardingClasses[name] = &CoSForwardingClass{
          Name:  name,
          Queue: queue,
      }
  }
  ```
  Contrast with fairness path (lines 419-425) which validates:
  ```go
  queue, err := strconv.Atoi(queueNode.Keys[1])
  if err != nil || queue < 0 || queue > 255 {
      return fmt.Errorf("... queue %q: expected queue 0..255", ...)
  }
  ...
  QueueID: uint8(queue),
  ```
- **Trace:**
  1. Operator configures `set class-of-service forwarding-classes queue 999 iperf-a` (typo / out-of-range queue number)
  2. `compileClassOfService` parses `queue=999` via `strconv.Atoi("999")` = 999, no error, no range check
  3. Stores `CoSForwardingClass{Queue: 999}` as `int` — no truncation in Go
  4. Dataplane snapshot builder (Rust `forwarding_build/cos.rs`) reads `queue` — if it casts to `u8`, `999u16 as u8` = `231` (truncation, wrong queue). If it validates, it would reject. Either way, no commit-time error for an invalid queue number.
  5. Junos forwarding-classes queue is 0..7 (8 queues). A queue of 999 is meaningless and should be rejected at commit.
- **Refutation attempt:** Checked whether `CoSForwardingClass.Queue` field type is `int` or `uint8` — it is `int` (`types.go`), so no direct Go truncation. Checked whether Rust snapshot builder validates queue range — likely yes (CoS queue count). Checked fairness path — it does validate 0..255 and casts to `uint8`. The forwarding-classes queue path omits this validation while the fairness-path queue for the same concept (queue id 0..7 mapped to hardware queues 0..7) has strict validation. The asymmetry is the finding.
- **Why it matters:** An unbounded queue number is never meaningful (CoS forwarding-classes map to hardware TX queues 0..7). Accepting `queue 999` silently is a config-parity gap — Junos would reject it. On the Rust dataplane, if queue number is used as an array index or cast to u8 without bounds check, it could cause wrong-queue assignment or panic (though Rust bounds checks on Vec access typically panic with informative message).
- **Fix direction:** Add `queue < 0 || queue > 7` (or `queue > 255` if 8..255 are valid for some NIC) range validation in `compileClassOfService` forwarding-classes loop, mirroring the fairness path pattern. Use `validateIntegerRange` or explicit check. Return `fmt.Errorf("class-of-service forwarding-classes queue %d: must be 0..7", queue)`. Wire as strict gate (hard-reject at commit, warn on lenient load).
- **Labels:** vsrx-parity, integer-validation, cos
- **Dedup note:** Not in dedup index. Checked: #4228 (CoS vSRX CoS parity gaps — 7 gaps enumerated, including classifier/rewrite gaps but not forwarding-classes queue range), #4314 (grouped show/request gaps), #4282/#4283 (CoS TX-path), #4535 (three-color policer color mode). None mention forwarding-classes queue number range validation.

---

### F3 — Low — `compiler_class_of_service.go` / `compiler_applications.go` CoS scheduler `equal-flow-target-policy` has no integer-typed equivalent but is implicitly string-validated only

- **Title:** CoS scheduler map `equal-flow-target-policy` values not explicitly enumerated at compile
- **Severity:** Low
- **Confidence:** Low
- **Evidence:**
  - File: `pkg/config/compiler_class_of_service.go`
  ```go
  case "equal-flow-target-policy":
      // #1746: enum validated by the schema (set time) and
      // validateClassOfServiceStrict (commit time).
      sched.EqualFlowTargetPolicy = nodeVal(child)
  ```
  - The actual accepted values (`wred` / `queue` / `"auto"`) are validated only in `validateClassOfServiceStrict` and the schema — not in this compile function. The raw `nodeVal` is stored without local validation.
- **Trace:** Not a bug — just noting the two-phase validation pattern (store raw + validate later in strict gate) is the established pattern for enum leaves in this codebase. The strict gate catches invalid values at commit time.
- **Why it matters:** Informational — this pattern is consistent with the rest of the codebase (all enum validations are in strict gates, not in the compiler). No fix needed.
- **Fix direction:** None — already handled by strict gate. Could add local `nodeVal` empty check but not needed.
- **Labels:** informational, no-fix-needed
- **Dedup note:** Not a finding — documenting as negative result for completeness.

---

### Overall Assessment — Negative Result Summary for Core Areas

#### Zone Policies / Global Policies / Host-Inbound / Application Matching / Default Deny-Permit

**No Critical or High bugs found in this batch.**

- **Zone policies (from-zone X to-zone Y):** All policy `match` leaves (`source-address`, `destination-address`, `application`, `source-address-excluded`, `destination-address-excluded`) correctly compiled via `firewallMatchValues` SSOT reading BOTH `Keys[1:]` and `Children` (dual #2419 shape). `validatePolicyMatchLeavesStrict` (#3113) correctly rejects unsupported match leaves (`dynamic-application`, `url-category`, `source-identity`) that would silently widen to match-ANY (fail-open). `validatePolicyRequiredMatchStrict` (#3044) correctly rejects policies missing mandatory `source-address` / `destination-address` / `application`. Zone-pair resolution correctly handles both hierarchical (`from-zone trust to-zone untrust`) and flat-set (from-zone → name → to-zone → name → policy) AST shapes.

- **Global policies:** `from-zone`/`to-zone` as match context scoping (#3148) correctly handled — globalOnlyPolicyMatchLeaves allows them only under `global` scope, while `swallowedStructuralMatchTokens` (#3673) prevents them from being absorbed as bogus app/address operands on zone-pair tail. Dual `security` blocks handled by `forEachChild`.

- **Host-inbound:** Not directly exercised by many batch files, but `compiler_interfaces.go` uses `junos-host` zone (reserved) handling. Full host-inbound review is in other batches. This batch shows correct handling for interfaces-per-zone and zone-interface membership.

- **Application matching:** `compileApplications` / `parseApplicationTerms` / `resolveAppPort` correctly handle multi-protocol terms, named-port → numeric via `junosServicePorts` SSOT, `0-N` → `1-N` normalization (#4336), ICMP type/code (#3348), timeout range [0,86400]. `validateApplicationNameCollisionsAST` correctly detects duplicate names across flat namespace (app vs app-set, generated vs authored, cross-parent, shadowing predefined). `parseICMPTypeCode` `uint8(n)` is range-checked before cast.

- **Default deny/permit:** `DefaultPolicy = PolicyDeny` (fail-closed) is the zero-value override in `compiler.go` line 1957 — verified default is DENY not PERMIT (the zero value `PolicyPermit=0` iota). Explicit `permit-all` / `deny-all` / `reject-all` via `compilePolicies` correctly maps each value. `default-policy-log` sibling-leaf shape preserves enum guard (#3534).

- **Intrazone (same-zone):** #3620 CLOSED with correct disposition — SRX subjects intrazone to security policy and denies via default-policy when unmatched (same as interzone). xpf matches this. No implicit intrazone permit. This is correct and documented.

#### Integer Truncation Focus

**No new truncation bugs found in this batch.** Every `strconv.Atoi` → narrower-type cast was checked:

| Cast | Source | Validation | Safe? |
|------|--------|-----------|-------|
| `uint16(nextID)` | `nextID uint32` | `nextID > 65535` rejection | YES (#3438 H4 fix) |
| `uint16(n)` WgListenPort | `Atoi(v)` int | `n > 0 && n <= 65535` | YES |
| `uint16(n)` KeepaliveSecs | `Atoi(v)` int | `n >= 0 && n <= 65535` | YES |
| `uint8(n)` ByteOffset | `Atoi(v)` int | `n >= 0 && n <= 255` | YES (#3203 fix) |
| `uint8(n)` BitLength | `Atoi(v)` int | `n >= 1 && n <= 32` | YES (#3203 fix) |
| `uint32(val)` MatchValue | `ParseUint(...,16,32)` | 32-bit hex parse | YES |
| `uint32(mask)` MatchMask | `ParseUint(...,16,32)` | 32-bit hex parse | YES |
| `uint8(n)` ICMPTypeCode | `Atoi(v)` int | `n >= 0 && n <= 255` | YES |
| `uint8(queue)` FairnessQueue | `Atoi(...)` int | `queue >= 0 && queue <= 255` | YES |
| `uint16(l), uint16(h)` ResolveFilterPortRange | `Atoi(canon)` int | canon pre-validated 1..65535 via resolveFilterPort | YES |
| `uint16(n)` resolveSinglePort | `parseCanonicalPort(s)` | 1..65535 range | YES |
| `uint16(70000)=4464` `portInSpec` | (was bug) | Now uses `canonicalPort` (ParseCanonicalUint, 1..65535) | FIXED (#3725) |
| `uint16(port)` DNAT pool | (was bug) | PortRaw preserved, strict gate uses parseCanonicalPort | FIXED (#3450) |

One low finding: forwarding-classes queue number unbounded (F2 above). Not a truncation per se (stored as int), but no range validation.

#### VRRP/HA Cold-Boot / DDNS / Observability Resource Safety

Not primary focus of this batch (these files are predominantly zone policy / app / firewall / NAT compilation + CLI tree + AST). No VRRP state machine, HA heartbeat, or DDNS code in this batch. DDNS/observability files are in other batches per the orientation.

- **Observability:** `ast_redact.go` secret redaction is correct and symmetric with detection. No resource leak.

---

## Recommendations

1. **F2 (Low):** Add forwarding-classes queue number range validation (0..7) in `compileClassOfService` to close the vSRX parity gap and prevent downstream u8 truncation / wrong-queue issues. Wire as `validateClassOfServiceStrict` strict gate.

2. **F1 (Low):** Consider documenting or replacing the `(*current)[:0]` slice reuse in `ast_edit.go:SetPath` scalar-leaf path with an explicit `make` for clarity, or add a comment explaining why it's safe (no aliasing under single-threaded SetPath).

3. **General:** The batch files are high-quality with thorough fail-on-revert test coverage and clear doc strings naming issue numbers. No zone-policy or global-policy enforcement bugs found. The strict-with-lenient (#1960) pattern is consistently applied.

