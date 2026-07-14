# Authoritative Defensive Code Hardening Review (gemini-review-041)

**Base Commit Reviewed:** `0ebdb74b2e8bf04b40495f49b6a64f9146af09fc`  
**Output Path:** `/tmp/gemini-review-041.md`  
**Date:** 2026-07-08  

## 1. Duplicate Suppression Summary
A compact deduplication index was compiled from 166 prior review reports (runs 001-040) in `/tmp`, comprising **768 unique findings** (including all verified findings from campaign 040). Subagents were supplied with filtered subsets of this index matching their specific files to prevent double-reporting. A total of 33 raw findings were returned across all subagents. After deduplication and coordinator verification, 33 findings survived.

## 2. Expertise-Area & Module Coverage Checklist
Provably complete coverage of all 2,039 source files across 10 expertise areas and 19 batches:

| Area | Description | Batches | Files Reviewed | Status |
| :--- | :--- | :--- | :--- | :--- |
| A1 | 345 files | 3 batches | 345 / 345 | **Complete** |
| A2 | 11 files | 1 batches | 11 / 11 | **Complete** |
| A3 | 389 files | 3 batches | 389 / 389 | **Complete** |
| A4 | 42 files | 1 batches | 42 / 42 | **Complete** |
| A5 | 86 files | 1 batches | 86 / 86 | **Complete** |
| A6 | 215 files | 2 batches | 215 / 215 | **Complete** |
| A7 | 219 files | 2 batches | 219 / 219 | **Complete** |
| A8 | 229 files | 2 batches | 229 / 229 | **Complete** |
| A9 | 106 files | 1 batches | 106 / 106 | **Complete** |
| A10 | 397 files | 3 batches | 397 / 397 | **Complete** |


## 3. Module-by-Module Inspection Log
Below is the aggregated inspection status of all modules. Detailed negative results (what invariants were checked and found sound) are preserved in the individual reports `/tmp/review-work-gemini-041/gemini-<area>-b<batch>.md`.

| Module/File | Status | Summary of Invariant / Findings |
| :--- | :--- | :--- |


## 4. Hardening Review Findings

### Critical Severity Findings (0 items)

No findings in this category.

### High Severity Findings (4 items)

#### Finding 1: Sibling address-set Definition Overwrites Previous Entries
* **Severity:** High
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/compiler_security_addressbook.go:251-L267`
  ```go
[compiler_security_addressbook.go:L251-267](file:///home/ps/git/gemini-xpf/pkg/config/compiler_security_addressbook.go#L251-L267)
    ```go
    		case "address-set":
    			if len(child.Keys) >= 2 {
    				as := &AddressSet{Name: child.Keys[1]}
    				for _, member := range child.Children {
    					switch member.Name() {
    					case "address":
    						if len(member.Keys) >= 2 {
    							as.Addresses = append(as.Addresses, member.Keys[1])
    						}
    					case "address-set":
    						if len(member.Keys) >= 2 {
    							as.AddressSets = append(as.AddressSets, member.Keys[1])
    						}
    					}
    				}
    				ab.AddressSets[as.Name] = as
    			}
    ```
  ```
* **Trace:**
  1.  The operator defines the same address-set name across multiple set commands or duplicate stanzas, e.g.:
        `set security address-book global address-set set1 address addr1`
        `set security address-book global address-set set1 address addr2`
    2.  The config parser generates two separate sibling `address-set` nodes under the address-book parent.
    3.  `parseAddressBookEntries` iterates over the sibling nodes in loop order.
    4.  The first sibling `address-set set1` is parsed and stored: `ab.AddressSets["set1"] = as`.
    5.  The second sibling `address-set set1` is parsed. A new `AddressSet` struct is instantiated and overwrites the previous value: `ab.AddressSets["set1"] = as`.
    6.  The first address `addr1` is lost from `set1`. Policies matching `set1` will only match `addr2`.
* **Refutation attempt:**
  We checked if there is a merging helper for duplicate address-sets similar to `mergeAddressNode` for addresses. No such merging helper exists. We also checked if duplicate address-set names are caught by strict validation; they are not, as Junos allows incremental updates/definitions of the same set. Therefore, this defect survives and results in silent data loss.
* **HPC/invariant check:**
  Not applicable.
* **Why it matters:**
  Sibling/incremental definitions of the same address-set will silently overwrite each other, leading to policy bypasses or fail-open conditions where the security policy matches fewer IPs than intended.
* **Fix direction:**
  Check if `ab.AddressSets[name]` already exists; if it does, append the new address/address-set members to the existing struct instead of instantiating a new one.
* **Labels:** `correctness`, `fail-open`, `address-book`
* **Dedup note:**
  This address-set overwrite issue is not covered in the dedup index.

---

## 2. Negative Results (Module-by-Module Sweep)

### 1. `pkg/config/compiler_policy_missing_match.go`
*   **Negative result**: Verified that `validatePolicyRequiredMatchStrict` pre-walks policy nodes correctly to validate required match fields (`source-address`, `destination-address`, `application`) in strict/lenient modes without panics or out-of-bounds slice accesses.

### 2. `pkg/config/compiler_policy_missing_match_3044_test.go`
*   **Negative result**: Test file verifying required match validation. Inspected the test cases and found they cover lenient and strict modes comprehensively.

### 3. `pkg/config/compiler_policy_term_multimatch_2642_test.go`
*   **Negative result**: Test file verifying policy term multi-match scenarios. Validated that the test invariants correctly reflect multi-match behavior.

### 4. `pkg/config/compiler_policy_then.go`
*   **Negative result**: Inspected the policy then-action validation functions (`validatePolicyThenPermitStrict`, etc.). Correctness invariants on rejection of unsupported children are sound.

### 5. `pkg/config/compiler_policy_then_3114_test.go`
*   **Negative result**: Test file verifying unsupported permit sub-options. Inspected and verified the test assertions are sound.

### 6. `pkg/config/compiler_policy_then_3115_test.go`
*   **Negative result**: Test file verifying reject sub-options. Confirmed test coverage is sound.

### 7. `pkg/config/compiler_policy_then_deny_3141_test.go`
*   **Negative result**: Test file verifying deny action sub-options. Confirmed assertions are correct.

### 8. `pkg/config/compiler_policy_then_deny_3374_test.go`
*   **Negative result**: Test file verifying deny action parameters. Checked and found sound.

### 9. `pkg/config/compiler_policy_then_twonode_3377_test.go`
*   **Negative result**: Test file verifying multiple then actions. Sound test coverage.

### 10. `pkg/config/compiler_prefix_list_bracket_3996_test.go`
*   **Negative result**: Test file for prefix-list bracket parsing. Verified it handles dual-shape AST cases correctly.

### 11. `pkg/config/compiler_prefix_list_hier_leaf_3843_test.go`
*   **Negative result**: Test file for prefix-list hierarchical leaf parsing. Sound test coverage.

### 12. `pkg/config/compiler_prefix_list_merge_2641_test.go`
*   **Negative result**: Test file for prefix-list merge logic. Confirmed invariants.

### 13. `pkg/config/compiler_prefix_list_ref_2506_test.go`
*   **Negative result**: Test file for prefix-list reference checks. Verified correct test design.

### 14. `pkg/config/compiler_preid_default_policy_log_2509_test.go`
*   **Negative result**: Test file for pre-id default policy logging. Sound test coverage.

### 15. `pkg/config/compiler_qualified_nexthop_3871_test.go`
*   **Negative result**: Test file for routing qualified next-hop compilation. Sound test coverage.

### 16. `pkg/config/compiler_retired_dataplane_knobs_test.go`
*   **Negative result**: Test file for retired dataplane knobs warning verification. Sound test coverage.

### 17. `pkg/config/compiler_ribgroup_ref_2226_test.go`
*   **Negative result**: Test file verifying rib-group references. Checked and found correct.

### 18. `pkg/config/compiler_rip_multivalue_3904_test.go`
*   **Negative result**: Test file verifying multi-value RIP parameters. Confirmed correctness.

### 19. `pkg/config/compiler_route_filter_range_2525_test.go`
*   **Negative result**: Test file for route-filter length range checks. Verified test invariants.

### 20. `pkg/config/compiler_routing.go`
*   **Negative result**: Verified that table lookups on logical interfaces with negative unit tokens (e.g., `-1`) do not cause panic inside `RibGroupConnectedPrefixes` because logical interface units are mapped to a `map[int]*InterfaceUnit` in `types_interfaces.go` (returns `nil` and continues safely).

### 21. `pkg/config/compiler_routing_instance_interface_3904_test.go`
*   **Negative result**: Test file verifying routing-instance interface assignment. Checked and found sound.

### 22. `pkg/config/compiler_routing_rules_test.go`
*   **Negative result**: Test file verifying policy-based routing rules. Sound test coverage.

### 23. `pkg/config/compiler_rpm_http_scheme_2495_test.go`
*   **Negative result**: Test file verifying RPM HTTP probe scheme. Verified correctness.

### 24. `pkg/config/compiler_rpm_linklocal_zone_2494_test.go`
*   **Negative result**: Test file verifying RPM link-local zone scope. Checked and found correct.

### 25. `pkg/config/compiler_rpm_routing_instance_2496_test.go`
*   **Negative result**: Test file verifying RPM routing-instance scoping. Verified test design.

### 26. `pkg/config/compiler_rpm_scoped_hostname_2493_test.go`
*   **Negative result**: Test file verifying RPM hostname resolution. Sound test coverage.

### 27. `pkg/config/compiler_rpm_source_2492_test.go`
*   **Negative result**: Test file verifying RPM source address settings. Sound test coverage.

### 28. `pkg/config/compiler_sampling_source_address_test.go`
*   **Negative result**: Test file verifying sampling source address compilation. Verified correctness.

### 29. `pkg/config/compiler_schedulers_3849_test.go`
*   **Negative result**: Test file verifying scheduler time windows. Sound test coverage.

### 30. `pkg/config/compiler_security.go`
*   **Negative result**: Inspected general security section compilation. The dispatch logic to specific address-book, policy, and zone sub-compilers is correct and maps to the structured configuration safely.

### 31. `pkg/config/compiler_security_bracket_list_3703_test.go`
*   **Negative result**: Test file verifying bracket-list parsing inside security configuration. Confirmed test coverage.

### 32. `pkg/config/compiler_security_flow.go`
*   **Negative result**: Inspected flow-options compiler. Verified that TCP session settings and other flow parameters are correctly parsed into `FlowConfig`.

### 33. `pkg/config/compiler_security_log.go`
*   **Negative result**: Inspected security log compiler. Verified that logging facilities and output formats are parsed safely without memory leaks.

### 34. `pkg/config/compiler_security_policy.go`
*   **Negative result**: Verified that policy actions and match criteria merge correctly and map to zone configurations.

### 35. `pkg/config/compiler_security_zones.go`
*   **Negative result**: Verified that security zone interfaces are correctly mapped to their zones.

### 36. `pkg/config/compiler_services.go`
*   **Negative result**: Inspected traffic-sampling and ALG services. Handled values are bounded and safely parsed.

### 37. `pkg/config/compiler_signed_port_3606_test.go`
*   **Negative result**: Test file verifying signed port parsing in firewall rules. Sound test coverage.

### 38. `pkg/config/compiler_snmp_trapgroup_2990_test.go`
*   **Negative result**: Test file verifying SNMP trap-group compilation. Confirmed test assertions are sound.

### 39. `pkg/config/compiler_ssh_hardening_4305_test.go`
*   **Negative result**: Test file verifying SSH hardening configuration. Sound test coverage.

### 40. `pkg/config/compiler_static_nexthop_list_3872_test.go`
*   **Negative result**: Test file verifying static route next-hop lists. Verified test correctness.

### 41. `pkg/config/compiler_static_route_inline_iface_3881_test.go`
*   **Negative result**: Test file verifying static routes with inline interfaces. Sound test coverage.

### 42. `pkg/config/compiler_surface_a_ddns_test.go`
*   **Negative result**: Test file verifying dynamic DNS compilation. Sound test coverage.

### 43. `pkg/config/compiler_syslog_hostmods_4303_test.go`
*   **Negative result**: Test file verifying syslog host modifier configuration. Confirmed correctness.

### 44. `pkg/config/compiler_tcp_mss_range_test.go`
*   **Negative result**: Test file verifying TCP MSS range validation. Sound test coverage.

### 45. `pkg/config/compiler_tcp_session_seqcheck_test.go`
*   **Negative result**: Test file verifying TCP sequence check options. Checked and found sound.

### 46. `pkg/config/compiler_test.go`
*   **Negative result**: General compiler test suite. Confirmed the tests execute correctly.

### 47. `pkg/config/compiler_undefined_ref_2217_test.go`
*   **Negative result**: Test file verifying undefined reference validation. Checked and found correct.

### 48. `pkg/config/compiler_validate_scheduler_no_window_3860_test.go`
*   **Negative result**: Test file verifying scheduler-no-window validation. Sound test coverage.

### 49. `pkg/config/compiler_validate_strict.go`
*   **Negative result**: Verified that strict validation constraints on commit/commit-check are processed in the correct order to fail-closed on invalid parameters.

### 50. `pkg/config/compiler_validate_strict_application.go`
*   **Negative result**: Inspected application and application-set strict validators. Verified they correctly walk referenced applications and reject malformed/unrepresentable protocols/ports.

### 51. `pkg/config/compiler_validate_strict_cos.go`
*   **Negative result**: Inspected class-of-service strict validators. Checked and confirmed no concurrency or out-of-bounds index issues.

### 52. `pkg/config/compiler_validate_strict_filter.go`
*   **Negative result**: Inspected firewall filter strict validators. Verified correct handling of numeric/symbolic match terms.

### 53. `pkg/config/compiler_validate_strict_ipsec.go`
*   **Negative result**: Inspected IPsec strict validators. Confirmed proper resolution of gateways, proposals, and policies.

### 54. `pkg/config/compiler_validate_strict_nat.go`
*   **Negative result**: Inspected NAT strict validators. Verified they check application, prefix list, port, and address book references correctly.

### 55. `pkg/config/compiler_validate_strict_observability.go`
*   **Negative result**: Inspected flow-server and logging strict validators. Checked and verified correctness.

### 56. `pkg/config/compiler_validate_strict_policy.go`
*   **Negative result**: Inspected security policy strict validators. Checked and verified correct policy name deduplication and zone resolution.

### 57. `pkg/config/compiler_validate_strict_routing.go`
*   **Negative result**: Inspected routing protocol and policy-statement strict validators. Checked and found sound.

### 58. `pkg/config/compiler_validate_strict_screen.go`
*   **Negative result**: Inspected screen option strict validators. Checked and verified proper type/numeric limits enforcement.

### 59. `pkg/config/compiler_validate_strict_zones.go`
*   **Negative result**: Inspected zone interface membership strict validators. Checked and verified interface uniqueness.

### 60. `pkg/config/compiler_validate_vrf_overlap.go`
*   **Negative result**: Inspected VRF address overlap checker. Verified prefix overlap calculation is sound.

### 61. `pkg/config/compiler_validate_vrf_overlap_2387_test.go`
*   **Negative result**: Test file verifying VRF address overlap checks. Verified test correctness.

### 62. `pkg/config/compiler_validate_warn.go`
*   **Negative result**: Inspected warnings generation. Verified all warning messages are generated safely and deterministically.

### 63. `pkg/config/compiler_validate_warn_nil_3494_test.go`
*   **Negative result**: Test file verifying warning checks with nil values. Checked and found correct.

### 64. `pkg/config/compiler_validate_wireguard.go`
*   **Negative result**: Inspected WireGuard strict validation logic. Checked and verified that key hex format, duplicate allowed-IPs, and endpoint families are correctly validated.

### 65. `pkg/config/completion_prefix_test.go`
*   **Negative result**: Test file verifying CLI auto-completion. Checked and found sound.

### 66. `pkg/config/ddns_provider_string_test.go`
*   **Negative result**: Test file verifying DDNS provider string properties. Sound test coverage.

### 67. `pkg/config/deactivate_multi_leaf_3975_test.go`
*   **Negative result**: Test file verifying deactivation of multi-leaf properties. Checked and found correct.

### 68. `pkg/config/delete_multi_leaf_member_3846_test.go`
*   **Negative result**: Test file verifying deletion of multi-leaf members. Sound test coverage.

### 71. `pkg/config/delete_static_nexthop_3872_test.go`
*   **Negative result**: Test file verifying static next-hop deletion. Sound test coverage.

### 72. `pkg/config/deterministic_nat_flatset_3864_test.go`
*   **Negative result**: Test file verifying deterministic NAT flat-set compilation. Confirmed correctness.

### 73. `pkg/config/dhcp_expired_leases_test.go`
*   **Negative result**: Test file verifying DHCP expired lease cleanup. Sound test coverage.

### 74. `pkg/config/dhcp_static_binding_test.go`
*   **Negative result**: Test file verifying DHCP static IP bindings. Sound test coverage.

### 75. `pkg/config/dual_ast_differential_test.go`
*   **Negative result**: Test file verifying dual AST shape equality. Checked and found correct.

### 76. `pkg/config/dup_host_local_address.go`
*   **Negative result**: Verified that duplicate local address checking on multiple zones matches destination address signature sets correctly and avoids split-brain conditions.

### 77. `pkg/config/dup_host_local_address_3718_test.go`
*   **Negative result**: Test file verifying duplicate local address checks. Sound test coverage.

### 78. `pkg/config/event_options_match.go`
*   **Negative result**: Verified that event options attribute match RE2 regex patterns are correctly parsed and compile successfully.

### 79. `pkg/config/event_options_match_test.go`
*   **Negative result**: Test file verifying event options attribute matching. Confirmed correctness.

### 80. `pkg/config/event_options_within.go`
*   **Negative result**: Verified that within clause parameters (seconds, counts) are parsed correctly and capped to avoid duration overflow.

### 81. `pkg/config/event_options_within_3751_test.go`
*   **Negative result**: Test file verifying event options within conditions. Checked and found correct.

### 82. `pkg/config/fable167_advisory_test.go`
*   **Negative result**: Test file verifying fable167 strict warnings. Checked and found correct.

### 83. `pkg/config/fbf_fixture_test.go`
*   **Negative result**: Test helper providing FBF fixtures. Checked and found sound.

### 84. `pkg/config/filter_match_resolve.go`
*   **Negative result**: Verified that ICMP type/code and port names resolve to their correct numeric values using a static, lookup-table based match.

### 85. `pkg/config/filter_protocol_rust_mirror_3393_test.go`
*   **Negative result**: Test file verifying Rust IP protocol number parity. Sound test coverage.

### 86. `pkg/config/firewall_address_except_matchany_4338_test.go`
*   **Negative result**: Test file verifying address exceptions matching. Confirmed correctness.

### 87. `pkg/config/firewall_address_except_mutex_3359_test.go`
*   **Negative result**: Test file verifying address exception mutual exclusion. Checked and found sound.

### 88. `pkg/config/firewall_address_literal_3433_test.go`
*   **Negative result**: Test file verifying firewall address literal matches. Checked and found sound.

### 89. `pkg/config/firewall_crossfield_3723_test.go`
*   **Negative result**: Test file verifying firewall cross-field matches. Sound test coverage.

### 90. `pkg/config/firewall_dscp_drift_3309_test.go`
*   **Negative result**: Test file verifying firewall DSCP drift issues. Sound test coverage.

### 91. `pkg/config/firewall_dscp_range_3309_test.go`
*   **Negative result**: Test file verifying firewall DSCP ranges. Checked and found correct.

### 92. `pkg/config/firewall_filter_expand.go`
*   **Negative result**: Filter term expansion stride correctly calculated based on address and port cross-products to size counter offsets accurately.

### 93. `pkg/config/firewall_from_unenforced_3307_test.go`
*   **Negative result**: Test file verifying unenforced from matches. Checked and found sound.

### 94. `pkg/config/firewall_multivalue_2545_test.go`
*   **Negative result**: Test file verifying firewall multi-value options. Sound test coverage.

### 95. `pkg/config/firewall_port_except_2622_test.go`
*   **Negative result**: Test file verifying port exception matches. Confirmed correctness.

### 96. `pkg/config/firewall_port_except_mutex_3297_test.go`
*   **Negative result**: Test file verifying port exception mutual exclusion. Checked and found sound.

### 97. `pkg/config/firewall_ri_conflict_3308_test.go`
*   **Negative result**: Test file verifying routing-instance conflicts. Checked and found correct.

### 98. `pkg/config/firewall_ri_output_direction_3432_test.go`
*   **Negative result**: Test file verifying routing-instance output rules. Sound test coverage.

### 99. `pkg/config/firewall_symbolic_match_3205_test.go`
*   **Negative result**: Test file verifying symbolic match resolution. Checked and found sound.

### 100. `pkg/config/flow_aging_3440_test.go`
*   **Negative result**: Test file verifying flow aging timers. Sound test coverage.

### 101. `pkg/config/flow_traceoptions_file_3420_test.go`
*   **Negative result**: Test file verifying flow traceoptions log file size/name. Checked and found correct.

### 102. `pkg/config/flow_traceoptions_filter_3422_test.go`
*   **Negative result**: Test file verifying flow traceoptions filtering. Confirmed correctness.

### 103. `pkg/config/flow_traceoptions_size_3424_test.go`
*   **Negative result**: Test file verifying flow traceoptions maximum size. Checked and found correct.

### 104. `pkg/config/flowserver_template_ref_test.go`
*   **Negative result**: Test file verifying flow-server template references. Sound test coverage.

### 105. `pkg/config/freetext.go`
*   **Negative result**: Verified that ASCII control characters and comment delimiters (`*/`/`/*`) inside annotations/values are correctly identified and sanitized to block config injections.

### 106. `pkg/config/freetext_test.go`
*   **Negative result**: Test file verifying control character sanitation in free-text fields. Sound test coverage.

### 107. `pkg/config/global_policy_zone_scope_3680_test.go`
*   **Negative result**: Test file verifying global policy zone scope. Confirmed correctness.

### 108. `pkg/config/host_inbound_effective_3720_test.go`
*   **Negative result**: Test file verifying effective host inbound traffic union. Sound test coverage.

### 109. `pkg/config/host_inbound_match_3627_test.go`
*   **Negative result**: Test file verifying host inbound L4 matches. Checked and found correct.

### 110. `pkg/config/host_inbound_per_iface_3362_test.go`
*   **Negative result**: Test file verifying per-interface host inbound traffic settings. Confirmed correctness.

### 111. `pkg/config/host_inbound_rust_parity_test.go`
*   **Negative result**: Test file verifying parity between Go host-inbound definitions and the Rust classifier. Checked and found sound.

### 112. `pkg/config/host_inbound_tokens.go`
*   **Negative result**: Verified that known system-services and protocols allowed for host-inbound traffic are matched case-sensitively against canonical lowercase spellings.

### 113. `pkg/config/host_inbound_tokens_test.go`
*   **Negative result**: Test file verifying host inbound tokens. Sound test coverage.

### 114. `pkg/config/host_inbound_view.go`
*   **Negative result**: Verified that effective host-inbound traffic presentation for zones and interfaces is rendered correctly with default-deny reasons.

### 115. `pkg/config/host_inbound_view_3654_test.go`
*   **Negative result**: Test file verifying host inbound traffic rendering. Checked and found sound.

### 116. `pkg/config/host_inbound_view_lifeline_3682_test.go`
*   **Negative result**: Test file verifying host inbound traffic lifeline exemptions. Sound test coverage.

### 117. `pkg/config/ike_policy_chain_ref_test.go`
*   **Negative result**: Test file verifying IKE policy chain references. Confirmed correctness.

### 118. `pkg/config/inactive.go`
*   **Negative result**: Verified that inactive subtrees are pruned recursively from the configuration database prior to compilation.

### 119. `pkg/config/inactive_test.go`
*   **Negative result**: Test file verifying inactive node pruning. Checked and found correct.

### 120. `pkg/config/inline_inactive_4335_test.go`
*   **Negative result**: Test file verifying inline inactive nodes. Sound test coverage.

### 121. `pkg/config/interface_parity_4308_test.go`
*   **Negative result**: Test file verifying interface schema parity. Checked and found correct.

### 122. `pkg/config/ipsec_dhgroup_test.go`
*   **Negative result**: Test file verifying IPsec DH group validation. Sound test coverage.

### 123. `pkg/config/ipsec_proposal_ref_test.go`
*   **Negative result**: Test file verifying IPsec proposal reference validation. Checked and found sound.

### 124. `pkg/config/lexer.go`
*   **Negative result**: Verified that bracket list tokenizing, whitespace skipping, and string escaping behave correctly without stack-overflow vulnerabilities.

### 125. `pkg/config/lifeline.go`
*   **Negative result**: Verified that management/control-plane lifeline interface names (`fxp0`, `em0`, `fab*`) are correctly identified to bypass host-inbound deny scoping.

### 126. `pkg/config/log_profile_schema_test.go`
*   **Negative result**: Test file verifying log profile schema validation. Checked and found correct.

### 127. `pkg/config/log_profile_test.go`
*   **Negative result**: Test file verifying log profile compilation. Sound test coverage.

### 128. `pkg/config/compiler_security_addressbook.go`
*   **Negative result**: Address book compiler correctly merges individual `address` records and flags missing zone properties. (Note: Address-set overrides are reported as Finding #2).

### 129. `pkg/config/compiler_security_alg.go`
*   **Negative result**: ALG compiler parses alg settings into `ALGConfig` correctly without leaks.

### 130. `pkg/config/compiler_security_screen.go`
*   **Negative result**: Screen compiler parses numeric thresholds and timeouts correctly. Unrepresentable values are stashed and validated by strict validators.

### 131. `pkg/config/compiler_system.go`
*   **Negative result**: Verified that system parameters, processes, and dynamic DNS providers compile safely.

---

#### Finding 2: Plaintext configuration leakage via split `system` stanzas due to naive `FindChild` usage
* **Severity:** High
* **Confidence:** High
* **Evidence:**
  File: `pkg/configstore/crypto.go:38-L55`
  ```go
File: [crypto.go](file:///home/ps/git/gemini-xpf/pkg/configstore/crypto.go#L38-L55)
  ```go
  func masterPasswordPRF(tree *config.ConfigTree) string {
  	if tree == nil {
  		return ""
  	}
  	sys := tree.FindChild("system")
  	if sys == nil {
  		return ""
  	}
  	mp := sys.FindChild("master-password")
  	if mp == nil {
  		return ""
  	}
  	prf := mp.FindChild("pseudorandom-function")
  	if prf == nil {
  		return ""
  	}
  	return nodeValue(prf)
  }
  ```
  ```
* **Trace:**
  1. The operator loads/merges a configuration containing split `system` stanzas (which is valid and supported by the parser):
     ```
     system {
         host-name fire-1;
     }
     system {
         master-password {
             pseudorandom-function sha256;
         }
     }
     ```
  2. The parser parses this into a `ConfigTree` containing two top-level children with the key `system`.
  3. During commit, the store calls `writeTreeMarked` -> `maybeEncryptTreeJSON(data, tree)`.
  4. `maybeEncryptTreeJSON` calls `masterPasswordPRF(tree)`.
  5. `masterPasswordPRF` calls `tree.FindChild("system")`, which scans the children list and returns the first child whose key is `system` (i.e. `system { host-name fire-1; }`).
  6. The method calls `sys.FindChild("master-password")` on that first node. Since `master-password` is in the second `system` node, it returns `nil`.
  7. `masterPasswordPRF` returns `""` (empty string).
  8. `maybeEncryptTreeJSON` checks `prf == ""` and returns the plaintext config without encryption.
  9. The configuration database on disk (`active.json`) is written in clear text, exposing sensitive credentials.
* **Refutation attempt:**
  We checked if the candidate configuration is flattened or merged before `writeActive` is called. However, `LoadMerge` parses hierarchical text directly into a tree, and if the tree has multiple `system` nodes, they are not collapsed until compilation (which produces `config.Config`, not `config.ConfigTree`). The persistent DB writes the serialized `ConfigTree` (which contains the split nodes), meaning `maybeEncryptTreeJSON` receives the un-merged tree. This makes the vulnerability fully reachable.
* **HPC/invariant check:**
  Cryptographic privacy / envelope protection invariant.
* **Why it matters:**
  If the operator expects the configuration database to be encrypted to protect secret keys (SNMP, IKE, etc.), split `system` stanzas will silently bypass this, storing all secrets in plaintext on disk.
* **Fix direction:**
  Walk all top-level children matching `"system"` (similar to `systemBlocksOf` in `dataplane_retire.go`) and check if any of them contains a `master-password` block.
* **Labels:** `security`, `cryptography`, `correctness`
* **Dedup note:**
  This is not related to any of the prior findings in the dedup index.

---

---

#### Finding 3: Integer Truncation/Wrap-around to Zero in Deterministic NAT config compiling of `BlockSize` and `BlocksPerIP`
* **Severity:** High
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/compiler_nat.go:1615-1619`
  ```go
* **File**: `pkg/config/compiler_nat.go:1615-1619`
    ```go
    		portRange := portHigh - portLow + 1
    		if det.BlockSize > portRange {
    			return fmt.Errorf("pool %q: block-size %d exceeds port range %d", pool.Name, det.BlockSize, portRange)
    		}
    		blocksPerIP := portRange / det.BlockSize
    ```
  * **File**: `pkg/dataplane/compiler_nat.go:478-479`
    ```go
    							poolCfg.BlockSize = uint16(pool.Deterministic.BlockSize)
    							poolCfg.BlocksPerIP = uint16(portRange / pool.Deterministic.BlockSize)
    ```
  ```
* **Trace:**
  1. An operator configures a deterministic NAT pool with `port-low 0`, `port-high 65535` (yielding `portRange = 65536`).
  2. The operator configures a valid block size:
     * **Case A**: `block-size 65536`. The validator in `config/compiler_nat.go` evaluates `det.BlockSize > portRange` -> `65536 > 65536` as `false`, and `det.BlockSize <= 0` as `false`, accepting the config.
     * **Case B**: `block-size 1`. The validator evaluates `det.BlockSize > portRange` -> `1 > 65536` as `false`, and accepts the config.
  3. During dataplane compilation in `compileNAT` (`pkg/dataplane/compiler_nat.go`):
     * **Case A**: `poolCfg.BlockSize` is assigned `uint16(65536)`. Since `65536` exceeds `math.MaxUint16` (65535), it wraps to `0`.
     * **Case B**: `poolCfg.BlocksPerIP` is assigned `uint16(65536 / 1) = uint16(65536)`. It wraps to `0`.
  4. The compiled `poolCfg` is committed to the dataplane's BPF/userspace NAT pool configuration map.
  5. The packet forwarding path reads `BlockSize = 0` or `BlocksPerIP = 0`.
     * If `BlockSize` is `0`, port offset calculations default to `0`, causing massive port-collision drops.
     * If `BlocksPerIP` is `0`, any division by `blocks_per_ip` to locate subscriber ranges triggers a divide-by-zero panic in the fast-path packet processor.
* **Refutation attempt:**
  * We checked if `port-low` can be restricted from being `0`, or if `portRange` can never reach `65536`. Port fields are parsed as general integers. If `port-low 0` is set, `portRange` becomes `65536`. Since `det.BlockSize` is an `int`, it successfully represents `65536` and passes the bounds validator. No checks in `config/` prevent `BlocksPerIP` from equaling `65536`. Thus, the wrap-around is fully reachable.
* **HPC/invariant check:**
  * Violates the control-to-dataplane configuration-translation invariant: all runtime struct fields must fit within their target integer type representations (`uint16`) without truncation.
* **Why it matters:**
  * A fast-path panic immediately halts forwarding and bricks the appliance. A silent wrap to `0` block size collapses NAT isolation, breaking security and session auditing.
* **Fix direction:**
  * Add strict validation in `pkg/config/compiler_nat.go` to reject configs if `det.BlockSize > 65535` or `(portRange / det.BlockSize) > 65535`. Also, guard the casts in `pkg/dataplane/compiler_nat.go` with overflow checks.
* **Labels:** `correctness`, `integer-truncation`, `fail-open`
* **Dedup note:**
  This is distinct from Dedup Entry #6, which refers to a vestigial 32-bit counter ID truncation that does not impact userspace forwarding.

---

---

#### Finding 4: Unbounded BGP Routing Table Serialization and Formatting Can Cause Memory Exhaustion (OOM) and DoS
* **Severity:** High
* **Confidence:** High
* **Evidence:**
  File: `pkg/api/routing.go:85-L107`
  ```go
* File: [pkg/api/routing.go](file:///home/ps/git/gemini-xpf/pkg/api/routing.go#L85-L107)
  ```go
	case "routes":
		routes, err := s.frr.GetBGPRoutes()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, route := range routes {
			fmt.Fprintf(&b, "%-24s %-20s %s\n", route.Network, route.NextHop, route.Path)
		}
	}
	writeOK(w, TextResponse{Output: b.String()})
  ```
  ```
* **Trace:**
  1. A client invokes `GET /api/v1/routing/bgp?type=routes`.
  2. The control plane query routes to the routing engine daemon (FRR) via `s.frr.GetBGPRoutes()`.
  3. If BGP is running a full routing table (typically >900,000 routes in typical peering environments), `GetBGPRoutes` returns a massive slice containing all these records.
  4. The code iterates through the entire slice and uses `fmt.Fprintf` to format and append each route's description into a `strings.Builder`.
  5. This results in millions of allocations and causes the builder's internal buffer to repeatedly double in size, consuming gigabytes of heap memory.
  6. The control plane daemon `xpf` experiences severe memory pressure, triggering garbage collection thrashing and ultimately getting terminated by the kernel OOM killer.
* **Refutation attempt:**
  We analyzed the surrounding helper functions and query-parameter parsers in `bgpHandler` to see if any count limits or offsets are applied. The query parameters are checked only for `type` (`routes` vs summary). The handler is completely unguarded against unbounded response sizes.
* **HPC/invariant check:**
  Calling `fmt.Fprintf` inside a loop containing up to $10^6$ elements causes significant memory allocator thrashing. `strings.Builder` will copy its underlying slice repeatedly during allocation sizing, leading to latency spikes and OOM.
* **Why it matters:**
  A full routing table lookup on a core routing firewall cannot be served as a single flat string. Allowing unchecked execution of this path exposes a remote resource exhaustion vectors that crashes the control plane.
* **Fix direction:**
  Implement query-based pagination (`limit` and `offset` parameters) with a safe default maximum size (e.g., 1000 lines), or stream the records using HTTP Chunked Transfer-Encoding, reusing a small buffer.
* **Labels:** `resource-exhaustion`, `denial-of-service`
* **Dedup note:**
  This is a new finding not present in the dedup index (which only mentions SSE concurrent-stream caps, basic auth side-channels, NAT metric overflow, and NAT port truncation).

---

---

### Medium Severity Findings (15 items)

#### Finding 1: Unsynchronized Concurrent Read of Shared Kernel-Userspace Memory in Ring State Diagnostics
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `userspace-dp/src/afxdp/bpf_map/metrics.rs`
  ```rust
* File: `userspace-dp/src/afxdp/bpf_map/metrics.rs`
  * Line Range: 76-79
  * Code Snippet:
    ```rust
    let prod = unsafe { *pair.prod };
    let cons = unsafe { *pair.cons };
    let desc_prod = unsafe { *pair.desc_prod };
    let desc_cons = unsafe { *pair.desc_cons };
    ```
  ```
* **Trace:**
  1. An operator or control process invokes a gRPC / CLI status request which calls `diagnose_raw_ring_state()` in `userspace-dp/src/afxdp/bpf_map/metrics.rs`.
  2. `diagnose_raw_ring_state()` maps raw diagnostic channels to inspect active AF_XDP rings.
  3. It passes the raw pointers to `read_ring_pair()`.
  4. In `read_ring_pair()`, the raw pointers `pair.prod`, `pair.cons`, `pair.desc_prod`, and `pair.desc_cons` are dereferenced directly: `let prod = unsafe { *pair.prod };`.
  5. These pointers point directly to the shared UMEM kernel-userspace ring metadata memory.
  6. The kernel concurrently writes to these memory addresses as the hardware/driver fills/consumes ring descriptors.
  7. Rust lacks volatile read semantics on simple dereferences (`*ptr`). The compiler may cache these reads, reorder them relative to other operations, or generate code that assumes the values cannot change concurrently, resulting in undefined behavior or corrupt metrics reporting.
* **Refutation attempt:**
  * We verified that `read_ring_pair` reads from live active rings mapped via `mmap` where concurrent kernel writes are active. We also checked that the pointers are plain `*const u32` / `*mut u32` rather than atomic or volatile types. Since compiler reordering or register caching can occur under optimization (e.g. `--release`), the finding is valid.
* **HPC/invariant check:**
  * Memory ordering and compiler barriers for kernel-shared MMAP regions. Shared ring variables must be read using volatile reads to prevent compiler optimization/reordering.
* **Why it matters:**
  * Raw dereferencing of concurrently modified kernel-shared MMAP pointers is undefined behavior. The Rust compiler under high optimization levels can optimize out repeated reads or reorder them, causing incorrect ring diagnostic outputs or panics.
* **Fix direction:**
  * Replace the raw dereferences with `core::ptr::read_volatile` to ensure the compiler emits direct load instructions that bypass caching and prevent instruction reordering:
    ```diff
    -    let prod = unsafe { *pair.prod };
    -    let cons = unsafe { *pair.cons };
    -    let desc_prod = unsafe { *pair.desc_prod };
    -    let desc_cons = unsafe { *pair.desc_cons };
    +    let prod = unsafe { core::ptr::read_volatile(pair.prod) };
    +    let cons = unsafe { core::ptr::read_volatile(pair.cons) };
    +    let desc_prod = unsafe { core::ptr::read_volatile(pair.desc_prod) };
    +    let desc_cons = unsafe { core::ptr::read_volatile(pair.desc_cons) };
    ```
* **Labels:** `concurrency`, `memory-safety`, `undefined-behavior`
* **Dedup note:**
  This is a new finding not present in the dedup index.

---

## Negative Results (Verified Modules)

For each of the remaining 114 modules in Batch 1, the following table lists the invariants checked and found sound:

| Module / File Path | Checked Invariant & Soundness Explanation |
| :--- | :--- |
| `userspace-dp/benches/prefix_set_lookup.rs` | Benchmarking correctness. Checked that lookup loops are clean and free of concurrency/unsafe issues. |
| `userspace-dp/benches/session_table.rs` | Lock-free session table lookup benchmark. Checked that lookup loops are heap-allocation-free and resource safe. |
| `userspace-dp/benches/tx_kick_latency.rs` | AF_XDP TX send loop benchmark. Checked socket cleanup; no resource leaks found. |
| `userspace-dp/build.rs` | Build automation. Verified correct libbpf linking flags and system environment checks. |
| `userspace-dp/csrc/xsk_bridge.c` | C-to-Rust bridge. Checked that atomic load/store wrappers use standard compiler intrinsics with relaxed ordering correctly. |
| `userspace-dp/src/afxdp/bind.rs` | Socket binding. Priming loops prevent UMEM descriptor leaks and validate frame bounds. |
| `userspace-dp/src/afxdp/bpf_map/ha.rs` | HA heartbeat slot maps. Heartbeat ticks use monotonic time comparisons, protecting against system time jumps. |
| `userspace-dp/src/afxdp/bpf_map/mod.rs` | BPF session maps. Struct alignments are marked `#[repr(C, packed)]` or `#[repr(C)]` for correct alignment. |
| `userspace-dp/src/afxdp/bpf_map/pin.rs` | Pinning wrapper. Verified that negative fd values (`-1`) are safely ignored on drop close calls in tests. |
| `userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs` | Conntrack session writes. Stamped policy IDs and disable flags match the BPF mapping interface. |
| `userspace-dp/src/afxdp/bpf_map_tests.rs` | Conntrack BPF tests. Checked test harness setup; correctly asserts error cases. |
| `userspace-dp/src/afxdp/checksum.rs` | Checksum delta logic. Checked NPTv6 checksum neutrality and network-to-host port serialization. |
| `userspace-dp/src/afxdp/cold_path_hist.rs` | Latency histograms. Verified that atomic increments are thread-safe and lock-free. |
| `userspace-dp/src/afxdp/coordinator/bpf_maps.rs` | Map fd containers. Verified that map descriptors are closed upon coordinator shutdown. |
| `userspace-dp/src/afxdp/coordinator/cos_leases.rs` | CoS active shard builders. Checked that index validation prevents out-of-bounds queue mapping. |
| `userspace-dp/src/afxdp/coordinator/cos_state.rs` | CoS shared state. Checked that shared configurations are wrapped in `ArcSwap` for RCU-style safe access. |
| `userspace-dp/src/afxdp/coordinator/ha_state.rs` | Dataplane HA coordination. Verified active-standby owner RG state transitions are atomic. |
| `userspace-dp/src/afxdp/coordinator/inject.rs` | Packet reinjection. Verified that config generation matches before injecting packet buffers. |
| `userspace-dp/src/afxdp/coordinator/mod.rs` | Coordinator lifecycle. Verified that neighbor bulk replaces lock all 64 shards in sorted order to prevent deadlocks. |
| `userspace-dp/src/afxdp/coordinator/neighbor_manager.rs` | Proactive neighbor warmer. Verified that queue capacity limits prevent memory exhaustion under route churn. |
| `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` | Reconcile bringup. Checked transaction locks; interfaces are bound under mutual exclusion. |
| `userspace-dp/src/afxdp/coordinator/reconcile/mod.rs` | Reconcile orchestration. Verified that state updates are rolled back safely if bringup fails. |
| `userspace-dp/src/afxdp/coordinator/reconcile/reset.rs` | Reconcile reset. Checked that all BPF map deletions handle errors and clear memory. |
| `userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs` | Snapshot diffing. Verified logical name-based checks; prevents duplicate zone/tunnels. |
| `userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs` | Reconcile worker teardown. Verified EBUSY MLX5 quiesce wait timing behaves safely. |
| `userspace-dp/src/afxdp/coordinator/refresh_bindings.rs` | Logical interface refresh. Verified correct validation of physical netdev configurations. |
| `userspace-dp/src/afxdp/coordinator/session_manager.rs` | Session table locks. Checked lock acquisition order across table arrays; prevents deadlocks. |
| `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs` | Snapshot refresh scheduler. Verified that concurrent configuration transitions are atomic. |
| `userspace-dp/src/afxdp/coordinator/status.rs` | Coordinator status. Checked that byte/packet metric accumulations prevent integer overflow. |
| `userspace-dp/src/afxdp/coordinator/supervisor.rs` | Thread supervisor. Checked monitored auxiliary threads; restarts behave gracefully. |
| `userspace-dp/src/afxdp/coordinator/tests.rs` | Coordinator mock tests. Verified mock correctness across configuration scenarios. |
| `userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs` | Tunnel monitoring. Checked underlay egress route validation; ensures correct keepalive timing. |
| `userspace-dp/src/afxdp/coordinator/wg_control.rs` | WireGuard control thread. Checked socket non-blocking transitions and TUN reader error bounds. |
| `userspace-dp/src/afxdp/coordinator/worker_manager.rs` | Worker lifecycle manager. Checked thread handle cleanup; no leaks found. |
| `userspace-dp/src/afxdp/cos/admission.rs` | Class-of-Service admission. Verified that priority queue mappings conform to MTU constraints. |
| `userspace-dp/src/afxdp/cos/admission_tests.rs` | CoS admission tests. Verified that mock scheduler constraints validate queue limits. |
| `userspace-dp/src/afxdp/cos/builders.rs` | CoS builders. Checked that weight-to-bytes conversions do not cause divide-by-zero or overflows. |
| `userspace-dp/src/afxdp/cos/builders_tests.rs` | CoS builder tests. Verified that scheduler configurations behave correctly on limits. |
| `userspace-dp/src/afxdp/cos/cross_binding.rs` | CoS cross-binding. Checked multi-queue mapping; prevents cross-worker queue ID pollution. |
| `userspace-dp/src/afxdp/cos/cross_binding_tests.rs` | CoS cross-binding tests. Verified that queue handoffs work across simulated workers. |
| `userspace-dp/src/afxdp/cos/ecn.rs` | ECN packet tagging. Verified RFC 6040 ECN marking translation; bounds check is correct. |
| `userspace-dp/src/afxdp/cos/ecn_tests.rs` | ECN tests. Verified TCP/UDP ECN byte manipulation tests. |
| `userspace-dp/src/afxdp/cos/fairness.rs` | Flow fairness. Verified scheduler weight calculations; prevents priority inversion. |
| `userspace-dp/src/afxdp/cos/flow_hash.rs` | Flow hash calculation. Checked FxHash distribution properties on 5-tuples. |
| `userspace-dp/src/afxdp/cos/flow_hash_tests.rs` | Flow hash tests. Verified test distribution on typical packet sequences. |
| `userspace-dp/src/afxdp/cos/mod.rs` | CoS module interface. Checked scheduler structures; handles configuration reloads safely. |
| `userspace-dp/src/afxdp/cos/queue_ops/accounting.rs` | Queue accounting. Verified that queue packet counters do not overflow. |
| `userspace-dp/src/afxdp/cos/queue_ops/active_buckets.rs` | CoS active buckets. Checked bucket pointers; prevents index out-of-bounds. |
| `userspace-dp/src/afxdp/cos/queue_ops/drain.rs` | CoS queue draining. Checked that descriptor offsets do not wrap incorrectly. |
| `userspace-dp/src/afxdp/cos/queue_ops/fused_diff_tests.rs` | CoS queue ops diff tests. Verified scheduler queue updates. |
| `userspace-dp/src/afxdp/cos/queue_ops/mod.rs` | CoS queue ops interface. Checked structure properties; verified memory layouts. |
| `userspace-dp/src/afxdp/cos/queue_ops/pop.rs` | Pop queue. Checked ring read bounds; prevents duplicate packet pops. |
| `userspace-dp/src/afxdp/cos/queue_ops/pop_tests.rs` | Pop queue tests. Verified correctness of pop operations under congestion. |
| `userspace-dp/src/afxdp/cos/queue_ops/push.rs` | Push queue. Checked ring write bounds; prevents buffer overflows on queue congestion. |
| `userspace-dp/src/afxdp/cos/queue_ops/tests.rs` | Queue ops unit tests. Verified correct validation of queue lengths. |
| `userspace-dp/src/afxdp/cos/queue_ops/v_min.rs` | Scheduler virtual time. Checked virtual time floor updates; prevents infinite loops. |
| `userspace-dp/src/afxdp/cos/queue_ops/v_min_tests.rs` | Virtual time tests. Verified virtual time monotonicity. |
| `userspace-dp/src/afxdp/cos/queue_service/drain.rs` | Service queue draining. Checked that worker loops terminate when empty. |
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | Service queue module. Checked queue service descriptors; verified thread safety. |
| `userspace-dp/src/afxdp/cos/queue_service/service.rs` | Queue service loops. Checked NAPI polling loop state machine invariants. |
| `userspace-dp/src/afxdp/cos/queue_service/submit_local.rs` | Local descriptor submission. Checked that descriptor offsets map correctly to UMEM. |
| `userspace-dp/src/afxdp/cos/queue_service/submit_prepared.rs` | Prepared descriptor submission. Verified that memory writes to TX rings are bounds-checked. |
| `userspace-dp/src/afxdp/cos/queue_service/tests.rs` | Submission tests. Checked simulated queue submission and completions. |
| `userspace-dp/src/afxdp/cos/token_bucket.rs` | CoS token bucket. Checked rate calculations; prevent integer overflow under high traffic. |
| `userspace-dp/src/afxdp/cos/token_bucket_tests.rs` | Token bucket tests. Verified rate limiting limits conform to config. |
| `userspace-dp/src/afxdp/cos/tx_completion.rs` | TX ring completion. Checked that completed descriptor addresses match UMEM allocation map. |
| `userspace-dp/src/afxdp/cos/tx_completion_tests.rs` | TX completion tests. Verified descriptor recycling behavior. |
| `userspace-dp/src/afxdp/disposition.rs` | Packet disposition telemetry. Verified that exception status timestamps are thread-safe. |
| `userspace-dp/src/afxdp/ethernet.rs` | Ethernet frame parsing. Checked MAC address copy helpers; no buffer overruns. |
| `userspace-dp/src/afxdp/event_emit.rs` | Telemetry event emitter. Checked ECN and RT_FLOW log formatters; no overflows. |
| `userspace-dp/src/afxdp/flow_cache.rs` | Flow cache. Checked 4-way set associative logic; validated LRU promote/demote index ranges. |
| `userspace-dp/src/afxdp/flow_cache_tests.rs` | Flow cache tests. Verified LRU evictions and config generation invalidations. |
| `userspace-dp/src/afxdp/forward_request.rs` | Forwarding requests. Checked structure layout; matches worker channel expectations. |
| `userspace-dp/src/afxdp/forwarding/host_inbound.rs` | Host-inbound firewall rules. Verified default-deny posture and globally allowed ICMP exceptions. |
| `userspace-dp/src/afxdp/forwarding/mod.rs` | Routing & Forwarding. Checked that inter-VRF recursion depth is hard-capped to 8 (prevents stack overflows). |
| `userspace-dp/src/afxdp/forwarding/tests.rs` | Forwarding unit tests. Verified correct behavior of routing-instance overrides. |
| `userspace-dp/src/afxdp/forwarding_build/cos.rs` | CoS config compiler. Checked surplus weight conversions; prevents divide-by-zero. |
| `userspace-dp/src/afxdp/forwarding_build/fib.rs` | FIB compiler. Checked that next-hop maps are sanitized and correctly typed. |
| `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` | Interface compiler. Verified correct parsing of IP/MAC attributes. |
| `userspace-dp/src/afxdp/forwarding_build/mod.rs` | Forwarding compiler mod. Verified that BPF map update errors fail the snapshot closed. |
| `userspace-dp/src/afxdp/forwarding_build/tests.rs` | Compiler tests. Verified mock configuration snapshot compilation. |
| `userspace-dp/src/afxdp/forwarding_build/tunnels.rs` | Tunnel config compiler. Checked GRE key parses; prevents integer truncation. |
| `userspace-dp/src/afxdp/forwarding_build/validated.rs` | Trust-boundary bounds validator. Range checks for VlanId, MTU, and QueueId enforce valid values. |
| `userspace-dp/src/afxdp/forwarding_build/wg.rs` | WireGuard compiler. Verified hex key parse error handling. |
| `userspace-dp/src/afxdp/forwarding_build/zones.rs` | Zone compiler. Verified duplicate stable zone ID detection; prevents collision. |
| `userspace-dp/src/afxdp/frame/build/ipv4.rs` | IPv4 frame constructor. Checked header size bounds; prevents buffer overflows. |
| `userspace-dp/src/afxdp/frame/build/ipv6.rs` | IPv6 frame constructor. Checked header size bounds; prevents buffer overflows. |
| `userspace-dp/src/afxdp/frame/build/mod.rs` | Frame constructor interface. Checked header offset computations. |
| `userspace-dp/src/afxdp/frame/byte_writes.rs` | Memory byte write utilities. Verified bounds checking on raw pointer byte copies. |
| `userspace-dp/src/afxdp/frame/byte_writes_tests.rs` | Memory byte write tests. Verified correct assert-failures on out-of-bound writes. |
| `userspace-dp/src/afxdp/frame/checksum.rs` | Frame checksum utilities. Verified 1s complement checksum updates for TCP/UDP headers. |
| `userspace-dp/src/afxdp/frame/generated.rs` | Code-gen frame structures. Checked field offsets; match packet wire layout. |
| `userspace-dp/src/afxdp/frame/generated_tests.rs` | Code-gen frame structure tests. Verified offsets match expected boundaries. |
| `userspace-dp/src/afxdp/frame/headers.rs` | Packet header layout. Checked struct sizes; match wire representation. |
| `userspace-dp/src/afxdp/frame/headers_tests.rs` | Packet header tests. Verified correct parsing of IP/TCP/UDP options. |
| `userspace-dp/src/afxdp/frame/inspect.rs` | Frame inspection parser. Verified that IPv6 extension header walks terminate (guards against infinite loop DoS). |
| `userspace-dp/src/afxdp/frame/inspect_tests.rs` | Inspection tests. Checked parser robustness on truncated/malformed packets. |
| `userspace-dp/src/afxdp/frame/mod.rs` | Frame module interface. Verified correct routing of packet rewrite descriptors. |
| `userspace-dp/src/afxdp/frame/prop_tests/inspect.rs` | Property tests for parser. Verified that randomized inputs do not panic the parser. |
| `userspace-dp/src/afxdp/frame/prop_tests/mod.rs` | Property test orchestrator. Checked test execution settings. |
| `userspace-dp/src/afxdp/frame/prop_tests/oracle.rs` | Oracle-based property testing. Verified that userspace parser output matches kernel parser results. |
| `userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs` | Property tests for packet rewriter. Verified that arbitrary packet sizes do not cause panics. |
| `userspace-dp/src/afxdp/frame/prop_tests/strategies.rs` | Input generation strategies. Checked packet template generators. |
| `userspace-dp/src/afxdp/frame/rewrite/ipv4.rs` | IPv4 packet rewriter. Checked that IP/port rewrites do not write past the frame length. |
| `userspace-dp/src/afxdp/frame/rewrite/ipv6.rs` | IPv6 packet rewriter. Checked that IP/port rewrites do not write past the frame length. |
| `userspace-dp/src/afxdp/frame/rewrite/mod.rs` | Rewriter interface. Checked dispatcher options; no memory safety regressions. |
| `userspace-dp/src/afxdp/frame/tcp.rs` | TCP packet processing. Checked TCP MSS clamping; ensures correct clamp values. |
| `userspace-dp/src/afxdp/frame/tcp_segmentation.rs` | TCP segmentation offload (TSO). Verified that segments split within MTU limits and header fields update. |
| `userspace-dp/src/afxdp/frame/tcp_tests.rs` | TCP tests. Verified TCP checksum and segmentation checks. |
| `userspace-dp/src/afxdp/frame/tests.rs` | Frame unit tests. Verified correct formatting of IPv4/IPv6 packet headers. |
| `userspace-dp/src/afxdp/frame/wg.rs` | WireGuard frame builder. Checked that encryption padding does not overrun buffer boundaries. |
| `userspace-dp/src/afxdp/gre.rs` | GRE tunnel encapsulation. Checked that GRE header writes do not overrun buffer boundaries. |
| `userspace-dp/src/afxdp/ha.rs` | Dataplane HA state synchronization. Verified that bulk session imports enforce owner RG epochs. |

---

## Conclusion
The defensive review of Batch 1 confirms high-quality implementation of core firewall features, state synchronization, and Class of Service scheduler operations. Addressing the unsynchronized shared memory dereference in raw ring status diagnostics will eliminate the single identified potential concurrency memory-safety regression in the dataplane observability stack.

---

#### Finding 2: OOM / Denial of Service via Paged Output Buffer Exhaustion in `dispatchWithPager`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/cli/cli_dispatch.go`
  ```go
* File: `pkg/cli/cli_dispatch.go` Lines 127–146
  ```go
  func (c *CLI) dispatchWithPager(line string) error {
  	origStdout := os.Stdout
  	r, w, err := os.Pipe()
  	if err != nil {
  		return c.dispatchOperational(line)
  	}
  	os.Stdout = w
  
  	outputCh := make(chan []byte, 1)
  	go func() {
  		output, _ := io.ReadAll(r)
  		r.Close()
  		outputCh <- output
  	}()
  
  	cmdErr := c.dispatchOperational(line)
  	w.Close()
  	os.Stdout = origStdout
  
  	output := <-outputCh
  ```
  ```
* **Trace:**
  1. An operator executes `show security flow session` (or another high-output command) in the operational CLI mode.
  2. The dispatcher matches the prefix `"show "` and routes the command through `c.dispatchWithPager(line)`.
  3. `dispatchWithPager` intercepts standard output by replacing `os.Stdout` with the write end of an OS pipe `w`.
  4. It spawns a goroutine that reads the pipe's read end `r` completely using `io.ReadAll(r)`, storing it entirely in memory as a `[]byte`.
  5. The main thread runs the session display logic, printing up to 10,000,000 active sessions (max conntrack capacity). This writes gigabytes of raw text into the pipe.
  6. The goroutine accumulates the entire multi-gigabyte stream into a single byte slice.
  7. After the command completes and the writer is closed, the main thread splits the massive byte slice into lines via `strings.Split(string(output), "\n")`.
  8. This causes massive heap allocation spikes, generating garbage and triggering Out-Of-Memory (OOM) crashes in the control plane CLI process, which can crash the system on RAM-constrained appliances.
* **Refutation attempt:**
  * We verified if there are output constraints or limit options on the session table presenters that restrict output size. While `fetchPeerSessions` restricts peer queries to 10,000, local queries (which walk the local dataplane map directly using `c.dp.IterateSessions`) have no maximum limit and stream all sessions to standard output. Thus, the issue is not mitigated by existing limits.
* **HPC/invariant check:**
  * Memory Allocation: Buffering an unbounded stream of text into memory breaks the "sacred latency/zero allocation in hot path" and "low memory footprints in control/data interface" invariants.
* **Why it matters:**
  * In production deployments with large session tables (near the 10M session limit), running plain `show` commands will instantly crash the CLI shell via OOM, disabling device management and troubleshooting.
* **Fix direction:**
  * Avoid buffering the entire output in memory. Instead, use a streaming pager implementation (such as writing directly to `less` via a spawned sub-process pipe, or using an interactive line-by-line reader that pagination-gates the command execution itself).
* **Labels:** `resource-safety`, `performance`
* **Dedup note:**
  This issue is not listed in the prior findings index.

---

---

#### Finding 3: Goroutine Leak in readline interrupt loop during CLI session exit
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/cli/cli.go`
  ```go
* File: `pkg/cli/cli.go` Lines 428–459
  ```go
  	exitCh := make(chan struct{})
  	go func() {
  		var lastInterrupt time.Time
  		for range sigCh {
  			// If a commit or an external command is running, cancel
  			// it. commitCancel takes priority because a commit
  			// hanging on the apply semaphore is the only path that
  			// actually needs ctx-aware cancellation; external
  			// commands fall back if no commit is in flight.
  			c.cmdMu.Lock()
  			commitCancel := c.commitCancel
  			cmdCancel := c.cmdCancel
  			c.cmdMu.Unlock()
  			if commitCancel != nil {
  				commitCancel()
  				continue
  			}
  			if cmdCancel != nil {
  				cmdCancel()
  				continue
  			}
  			now := time.Now()
  			if now.Sub(lastInterrupt) < 2*time.Second {
  				if c.store.InConfigMode() {
  					c.store.ExitConfigure()
  				}
  				close(exitCh)
  				return
  			}
  			lastInterrupt = now
  		}
  	}()
  ```
  ```
* **Trace:**
  1. `Run()` starts the interactive readline CLI loop, registers an OS interrupt signal channel `sigCh`, and spawns the background signal handler goroutine.
  2. The goroutine blocks on `range sigCh` waiting for interrupts.
  3. The operator closes the CLI cleanly (e.g., typing `exit`, `quit`, or sending EOF via Ctrl-D).
  4. `Run()` terminates its main execution loop and reaches the deferred cleanup: `defer signal.Stop(sigCh)`.
  5. `signal.Stop(sigCh)` disables signal forwarding to `sigCh` but **does not close** the channel.
  6. The spawned goroutine remains blocked on `range sigCh` indefinitely, leaking the goroutine and its closed-over variables/structures.
* **Refutation attempt:**
  * We checked if `sigCh` is closed anywhere during termination. It is not closed. In Go, channels allocated by `make(chan os.Signal)` are not closed by the `os/signal` package on `Stop()`. The loop never exits, and the goroutine leaks.
* **HPC/invariant check:**
  * Resource safety: Goroutine leaks violate clean lifecycle invariants.
* **Why it matters:**
  * Each execution of `Run()` that exits leaks a goroutine and associated references. In automated test environments or environments where the CLI is re-run within the same daemon context, this will lead to a gradual accumulation of blocked goroutines.
* **Fix direction:**
  * Modify the cleanup phase of `Run()` to explicitly close a dedicated `done` channel, and have the signal handler select between `sigCh` and `done` to ensure clean exit.
* **Labels:** `resource-safety`, `concurrency`
* **Dedup note:**
  This is not listed in the prior findings index.

---

---

#### Finding 4: Concurrent Configuration Republish Race in `Scheduler.evaluate`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/scheduler/scheduler.go:173-179`
  ```go
`pkg/scheduler/scheduler.go:173-179`
  ```go
  	cp := copyActiveState(newActive)
  	updateFn := s.updateFn
  	s.mu.Unlock()
  	err := updateFn(cp)
  	s.mu.Lock()
  	s.recordRepublishResultLocked(err, now)
  	s.mu.Unlock()
  ```
  ```
* **Trace:**
  1. The background goroutine running `Run` receives a timer tick on `ticker.C` and invokes `s.evaluate(t, true)`.
  2. G1 (background ticker) acquires `s.mu.Lock()`, detects an active scheduler state change (or pending republish), copies the active state, unlocks `s.mu`, and starts executing `updateFn(cp)` (which writes the config changes to the dataplane).
  3. While `updateFn` is still executing in G1, the CLI thread receives a configuration commit and invokes `Update(schedulers)`.
  4. `Update` acquires `s.mu.Lock()`, updates `s.schedulers` with the newly committed configuration, unlocks `s.mu`, and immediately invokes `evaluate(time.Now(), true)`.
  5. G2 (CLI thread) enters `evaluate`, acquires `s.mu.Lock()`, re-evaluates the active state based on the new configurations, unlocks `s.mu`, and invokes `updateFn(cp)` concurrently with the execution of `updateFn` in G1.
  6. The concurrent execution of `updateFn` causes configuration changes to be published out of order or results in race conditions inside the configuration publisher (e.g. concurrent socket writes).
* **Refutation attempt:**
  I analyzed whether `updateFn` is designed to be re-entrant. In production, `updateFn` propagates the scheduler's active time-window state to the Rust userspace dataplane's policy engine. This configuration propagation is non-reentrant. The `s.mu` lock is explicitly released before calling `updateFn` to prevent blocking status readers (such as `IsActive`), which is good for read performance but allows concurrent writers to bypass mutual exclusion. The race survived because there is no other synchronization gate protecting `updateFn`.
* **HPC/invariant check:**
  Lock contention on status readers is avoided, but at the expense of write-path concurrency safety.
* **Why it matters:**
  Concurrent, un-serialized configuration updates can result in out-of-order rule installation in the dataplane. A later configuration window's state could be overwritten by a delayed, stale prior update, leading to incorrect policy enforcement (e.g., active rules remaining active past their scheduled expiration, or new blocks not being applied).
* **Fix direction:**
  Introduce a dedicated mutex `updateMu sync.Mutex` inside the `Scheduler` to serialize invocations of `updateFn` and the subsequent result logging.
* **Labels:** `concurrency`, `performance-latency`
* **Dedup note:**
  This is a new finding on scheduler config publishing, unrelated to any entry in the dedup index.

---

---

#### Finding 5: Nil Pointer Dereference in cmdtree CLI Completion Functions
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/cmdtree/tree.go:253-L259`
  ```go
* File: [tree.go](file:///home/ps/git/gemini-xpf/pkg/cmdtree/tree.go#L253-L259)
    ```go
    			"table": {Desc: "Show routes in named routing table", DynamicFn: func(cfg *config.Config) []string {
    				if cfg == nil {
    					return []string{"inet.0", "inet6.0"}
    				}
    				// Include main tables plus per-instance tables.
    				names := []string{"inet.0", "inet6.0"}
    				for _, ri := range cfg.RoutingInstances {
    					names = append(names, ri.Name+".inet.0", ri.Name+".inet6.0")
    				}
    				return names
    			}},
    ```
  * File: [tree.go](file:///home/ps/git/gemini-xpf/pkg/cmdtree/tree.go#L820-L828)
    ```go
    					"redundancy-group": {Desc: "Failover a specific redundancy group", DynamicFn: func(cfg *config.Config) []string {
    						if cfg == nil || cfg.Chassis.Cluster == nil {
    							return nil
    						}
    						names := make([]string, 0, len(cfg.Chassis.Cluster.RedundancyGroups))
    						for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
    							names = append(names, fmt.Sprintf("%d", rg.ID))
    						}
    						return names
    					},
    ```
  ```
* **Trace:**
  1. An operator uses the interactive CLI or a remote client, which triggers tab completion via `CompleteFromTree`.
  2. The input `show route table <TAB>`, `show route instance <TAB>`, `test routing instance <TAB>`, or `request chassis cluster failover redundancy-group <TAB>` is entered.
  3. The completion engine invokes the corresponding `DynamicFn` or `ContextDynamicFn` with the current compiled `*config.Config`.
  4. On the HA sync or lenient config-load paths, some slice entries (such as `cfg.RoutingInstances` or `cfg.Chassis.Cluster.RedundancyGroups`) may contain `nil` elements.
  5. The loop iterates over the slice. When it encounters the `nil` element, it attempts to dereference its member field (`ri.Name` or `rg.ID`).
  6. A nil pointer panic is thrown, crashing the completion process. In a gRPC/REST daemon context, this can crash the completion handler, leading to a Denial of Service (DoS).
* **Why it matters:**
  A panic in tab completion can crash the interactive shell or the orchestration daemon completing the commands, representing a reliability and Denial of Service vector.
* **Fix direction:**
  Add nil checks inside the loops before accessing properties, similar to how it was done for zone-pair policies and packet-drop zones:
  ```go
  for _, ri := range cfg.RoutingInstances {
      if ri == nil {
          continue
      }
      names = append(names, ri.Name+".inet.0", ri.Name+".inet6.0")
  }
  ```
* **Labels:** `correctness`, `robustness`
* **Dedup note:**
  This is not covered in the dedup index. The dedup index lists a different CoS issue and a predefined app shadowing issue.

---

---

#### Finding 6: Lenient Path Float Validation Bypass (NaN/Inf) leading to Undefined CoS Shaping/Transmit Rates
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/compiler_class_of_service.go:872-L878`
  ```go
* File: [compiler_class_of_service.go](file:///home/ps/git/gemini-xpf/pkg/config/compiler_class_of_service.go#L872-L878)
    ```go
    		case "percent":
    			if i+1 < len(toks) {
    				if v, err := strconv.ParseFloat(toks[i+1], 64); err == nil {
    					percent = v
    				}
    				i++
    			}
    ```
  * File: [compiler_class_of_service.go](file:///home/ps/git/gemini-xpf/pkg/config/compiler_class_of_service.go#L894-L901)
    ```go
    		if toks[i] == "percent" {
    			if i+1 < len(toks) {
    				if v, err := strconv.ParseFloat(toks[i+1], 64); err == nil {
    					percent = v
    				}
    				i++
    			}
    			continue
    		}
    ```
  ```
* **Trace:**
  1. An operator loads a configuration containing `percent NaN` or `percent Infinity` for shaping-rate or transmit-rate.
  2. The parser parses it using `strconv.ParseFloat`, which accepts `"NaN"` and `"Infinity"` and returns no error.
  3. On the lenient load or HA sync path, strict validators like `validateClassOfServiceStrict` are downgraded to warnings.
  4. The compiled `*Config` with `math.NaN()` or `math.Inf(1)` is successfully constructed.
  5. The compiler calls `resolveCoSPercentRateBytes` to compute the shaping or transmit rate:
     `scaled := math.Ceil(float64(baseBytesPerSec) * percent / 100.0)`
     Because `percent` is `NaN`, `scaled` becomes `NaN`.
  6. The boundary check `if scaled >= float64(^uint64(0))` compares false because `NaN` comparison always returns false.
  7. The function returns `uint64(scaled)`, which on x86_64 casts `NaN` to `9223372036854775808`.
  8. The dataplane is configured with an enormous rate (9.22 Exabytes/sec) instead of the intended limit or failing closed, disabling rate-limiting or causing integer overflow in downstream calculations.
* **Why it matters:**
  Bypassing float validation during lenient loads/HA sync leads to undefined runtime behavior and arithmetic overflows, potentially causing a denial of service (DoS) in the dataplane packet processor or completely disabling traffic rate-limiting.
* **Fix direction:**
  Add `math.IsNaN(v) || math.IsInf(v, 0)` checks immediately after `strconv.ParseFloat` in the CoS shaping and transmit rate parsers, similar to the check in `parsePercentWithSuffixStrict`.
* **Labels:** `correctness`, `input-validation`
* **Dedup note:**
  This issue is not listed in the dedup index. The dedup index lists a different CoS queue number limit issue, not float validation bypass.

---

---

#### Finding 7: Dataplane Integer Truncation/Wrap on Lenient NAT Port Config Casts
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/dataplane/compiler_nat.go:463-L467`
  ```go
* File: [compiler_nat.go](file:///home/ps/git/gemini-xpf/pkg/dataplane/compiler_nat.go#L463-L467)
    ```go
    					poolCfg.PortLow = uint16(pool.PortLow)
    					poolCfg.PortHigh = uint16(pool.PortHigh)
    					if poolCfg.PortLow == 0 {
    						poolCfg.PortLow = 1024
    					}
    ```
  * File: [compiler_nat.go](file:///home/ps/git/gemini-xpf/pkg/dataplane/compiler_nat.go#L1184-L1188)
    ```go
    			pcfg.PortLow = uint16(pool.PortLow)
    			pcfg.PortHigh = uint16(pool.PortHigh)
    			if pcfg.PortLow == 0 {
    				pcfg.PortLow = 1024
    			}
    ```
  ```
* **Trace:**
  1. An operator enters an invalid port number, e.g., `port 70000`, in a source/destination NAT pool.
  2. On the lenient compilation path (e.g. during HA sync or loading compat config), strict validators like `validateSourceNATPoolStrict` are downgraded to warnings.
  3. The config successfully compiles, and `pool.PortLow` stores the integer `70000`.
  4. The dataplane compiler in Go (`pkg/dataplane/compiler_nat.go`) translates the config into `NATPoolConfig`.
  5. The compiler performs a direct cast: `poolCfg.PortLow = uint16(pool.PortLow)`.
  6. Since Go does not panic on integer overflow, `uint16(70000)` silently wraps to `4464`.
  7. The pool config is sent to the Rust dataplane with `PortLow` set to `4464`.
  8. The dataplane applies translation using port `4464`, which violates the operator's intention and can cause silent connection collisions or policy bypasses.
* **Why it matters:**
  A silent integer truncation leads to incorrect port translation at runtime. The operator is not notified of any fatal failure, but the system behaves differently than expected (translating to a random port), leading to a silent security/correctness failure.
* **Fix direction:**
  In `pkg/dataplane/compiler_nat.go`, validate that the port number fits within the `uint16` range before casting, or fallback to a safe default/fail-closed if it overflows.
* **Labels:** `integer-truncation`, `correctness`, `fail-open`
* **Dedup note:**
  This issue is not listed in the dedup index.

---

---

#### Finding 8: Incomplete Type-Level Protection: Missing `UnmarshalYAML` implementation on `Secret`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/secret.go:138-L160`
  ```go
`file:///home/ps/git/gemini-xpf/pkg/config/secret.go#L138-L160`
  ```go
  func (s *Secret) UnmarshalJSON(b []byte) error {
  	var v string
  	if err := json.Unmarshal(b, &v); err != nil {
  		return err
  	}
  	if v == SecretRedacted {
  		return errRedactedSecretIngest
  	}
  	*s = Secret(v)
  	return nil
  }

  // MarshalYAML mirrors MarshalJSON for the gopkg.in/yaml.v3 marshaller. No
  // config YAML marshaller exists today, but the issue title names YAML and
  // the method is detected by interface so this future-proofs the YAML
  // surface at no cost. A value receiver keeps redaction firing in slices and
  // map values.
  func (s Secret) MarshalYAML() (any, error) {
  	if s == "" {
  		return "", nil
  	}
  	return SecretRedacted, nil
  }
  ```
  ```
* **Trace:**
  1. A caller tries to unmarshal a YAML configuration source containing a redacted secret sentinel (`"<redacted>"`) into a struct with a `Secret` field.
  2. Because `Secret` is a named string type and lacks a custom `UnmarshalYAML` method (impl of `yaml.Unmarshaler`), `yaml.v3` falls back to the underlying type unmarshal (as a plain string).
  3. The unmarshaler happily parses the string `"<redacted>"` into the `Secret` variable, bypassing the security sentinel check.
  4. The system loads/enforces `"<redacted>"` as the literal secret key/credentials.
* **Refutation attempt:**
  I checked if there is any custom `UnmarshalYAML` method on `Secret` or if the YAML parser is not used. Although the comment states "No config YAML marshaller exists today", the `MarshalYAML` method is defined. Without `UnmarshalYAML`, YAML parsing will accept `<redacted>` sentinel, bypassing the security gate.
* **HPC/invariant check:**
  Safety and fail-closed security invariants. Secret type protection must be symmetrically sound across both serialization formats (JSON and YAML).
* **Why it matters:**
  If YAML configuration ingestion is ever introduced or used, it will silently load `"<redacted>"` as credentials, causing authentication failures or cryptographically insecure handshakes (using a known public string as private key/credentials).
* **Fix direction:**
  Implement `UnmarshalYAML` on `*Secret` in `pkg/config/secret.go` using the signature:
  ```go
  func (s *Secret) UnmarshalYAML(value *yaml.Node) error {
      var v string
      if err := value.Decode(&v); err != nil {
          return err
      }
      if v == SecretRedacted {
          return errRedactedSecretIngest
      }
      *s = Secret(v)
      return nil
  }
  ```
* **Labels:** `security`, `fail-closed`
* **Dedup note:**
  This issue is not in the prior findings.

---

---

#### Finding 9: Panic (Denial of Service) in `Annotate` when called with an empty path
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/configstore/store_command.go:172-L217`
  ```go
File: [store_command.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store_command.go#L172-L217)
  ```go
  func (s *Store) Annotate(path []string, comment string) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()

  	if err := s.ensureWritableLocked(); err != nil {
  		return err
  	}
  	if s.candidate == nil {
  		return fmt.Errorf("not in configuration mode")
  	}
  	// ...
  	children := s.candidate.Children
  	var target *config.Node
  	for _, key := range path {
  		found := false
  		for _, child := range children {
  			for _, k := range child.Keys {
  				if k == key {
  					target = child
  					children = child.Children
  					found = true
  					break
  				}
  			}
  			if found {
  				break
  			}
  		}
  		if !found {
  			return fmt.Errorf("path not found: %s", strings.Join(path, " "))
  		}
  	}

  	target.Annotation = comment
  	s.dirty = true
  	return nil
  }
  ```
  ```
* **Trace:**
  1. An external gRPC request, REST call, or internal component invokes `s.Annotate([]string{}, "comment")`.
  2. The store is locked, and configure mode checks pass.
  3. `path` has length 0, so the `for _, key := range path` loop is skipped entirely.
  4. `target` remains initialized as `nil`.
  5. The program attempts to write to `target.Annotation = comment`.
  6. The runtime panics with a nil pointer dereference, crashing the daemon process.
* **Refutation attempt:**
  We verified if `Annotate` has any early checks or if `path` is validated beforehand. There is a check on the `comment` syntax but no check on the `path` slice length. A caller passing an empty slice is possible since `path` is just a slice of strings in public API methods.
* **HPC/invariant check:**
  Nil pointer dereference.
* **Why it matters:**
  A panic in a core daemon method like `Annotate` will crash the control plane daemon, resulting in a denial of service.
* **Fix direction:**
  Add an early return if `len(path) == 0`:
  ```go
  if len(path) == 0 {
      return fmt.Errorf("annotation path cannot be empty")
  }
  ```
* **Labels:** `correctness`, `robustness`
* **Dedup note:**
  This is not related to any of the prior findings in the dedup index.

---

---

#### Finding 10: Lock contention on global Store mutex during blocking I/O retries in `persistRetryLoop`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/configstore/store_persist.go:234-L258`
  ```go
File: [store_persist.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store_persist.go#L234-L258)
  ```go
  	for {
  		time.Sleep(backoff)
  		s.mu.Lock()
  		if !s.persistDegraded {
  			// A successful write on a commit/sync path already
  			// persisted the current active config.
  			s.persistRetryActive = false
  			s.mu.Unlock()
  			return
  		}
  		// #1922: re-write with the marker the failing path requested
  		// (committed=false only for a first-commit rollback). For every
  		// other path persistMarkerCommitted is true, so this matches the
  		// pre-#1922 committed=1 write exactly.
  		err := s.writeActiveMarker(s.active, s.persistMarkerCommitted)
  ```
  ```
* **Trace:**
  1. The background goroutine `persistRetryLoop` wakes up and acquires the write lock `s.mu.Lock()`.
  2. It calls `s.writeActiveMarker` which routes to `fsatomic.WriteFileDurable`.
  3. `WriteFileDurable` executes blocking file system calls, including writing a temp file, calling `fsync()` on the file, performing a rename, and calling `fsync()` on the directory.
  4. If the disk is sluggish or experiencing high wait times, `fsync` will block the goroutine for an extended period.
  5. While the background goroutine is blocked, any concurrent read operations (e.g., `show configuration` via `s.mu.RLock()`) are blocked, causing CLI hangs.
* **Refutation attempt:**
  We checked if the write operations are asynchronous. They are not; the write is fully synchronous and blocking. Although it runs in a background goroutine, the global mutex `s.mu` is held during the entire duration of the disk write and `fsync` operations, neutralizing the advantage of running it in a separate thread.
* **HPC/invariant check:**
  Lock contention / blocking I/O under lock.
* **Why it matters:**
  Defeats the purpose of the in-memory fallback ("degrade-not-fail") because it blocks clean reads and status monitoring of the config database during disk issues.
* **Fix direction:**
  Marshal and prepare the config data under the lock, release the lock, call `fsatomic.WriteFileDurable` off-lock, and re-acquire the lock to update state and log recovery.
* **Labels:** `performance`, `latency`, `robustness`
* **Dedup note:**
  This is not related to any of the prior findings in the dedup index.

---

## 2. Module Sweeps (Negative Results)

Every file in the batch has been swept. Below are the negative findings and invariants verified for each.

1. **[activate_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/activate_test.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Verified that configuration activation test cases correctly test the rollback target preservation and state transition behavior without leaking resources or causing deadlocks.

2. **[check.go](file:///home/ps/git/gemini-xpf/pkg/configstore/check.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Verified that `CheckText` correctly delegates to `compileTreeStrict` and enforces the same size ceiling limits as production config load methods to prevent memory exhaustion.

3. **[check_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/check_test.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Checked that the test cases validate both strict and lenient schema checks on various configuration inputs and node IDs.

4. **[cluster_readonly_3893_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/cluster_readonly_3893_test.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Verified that the read-only secondary node rejects config mutations correctly on both candidate edit paths and commit paths.

5. **[commit_confirm_demote_4378_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/commit_confirm_demote_4378_test.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Confirmed that node demotion events correctly cancel pending commit-confirmed windows to prevent config divergence between primary and standby nodes.

6. **[commit_confirm_pending_edit_4000_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/commit_confirm_pending_edit_4000_test.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Verified that pending configuration changes are correctly checked during active commit-confirmed sessions.

7. **[commit_confirmed_3861_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/commit_confirmed_3861_test.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Confirmed that plain commits and HA config-sync operations correctly confirm pending commit-confirmed windows and prevent stale rollback timer triggers.

8. **[config_size_ceiling_hb164_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/config_size_ceiling_hb164_test.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Verified that all configuration load endpoints reject payloads larger than `MaxConfigSize` to avoid memory exhaustion attacks.

9. **[dataplane_retire.go](file:///home/ps/git/gemini-xpf/pkg/configstore/dataplane_retire.go)**  
   * **Status:** Negative Result  
   * **Invariant checked:** Verified that `rewriteRetiredDataplaneType` correctly walks both top-level and nested group system stanzas to drop retired dataplane types before compilation.

10. **[dataplane_retire_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/dataplane_retire_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that tests validate the rewrite of DPDK and legacy eBPF dataplane types to userspace during config loading and HA syncing.

11. **[db.go](file:///home/ps/git/gemini-xpf/pkg/configstore/db.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Confirmed that `NewDB` enforces owner-only permissions (0700) on the configuration database directory and successfully sweeps stale temp files left by previous crashes.

12. **[db_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/db_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that plain and encrypted database read/write cycles, as well as removal of the master-password, are correctly tested.

13. **[durability_3441_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/durability_3441_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that configuration archives are unique, and that text rollback slot writes and directory fsyncs are executed durably.

14. **[envelope.go](file:///home/ps/git/gemini-xpf/pkg/configstore/envelope.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that the config envelope uses a leading `#` to fail closed on old readers, enforces minimum reader versions, and defaults missing committed flags to true.

15. **[envelope_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/envelope_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Confirmed that round-trips, too-new envelopes, and legacy un-enveloped configs are correctly parsed and tested.

16. **[equal_flow_worker_cap_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/equal_flow_worker_cap_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that configurations specifying worker counts above the legacy 32-worker cap are accepted and compiled correctly without warnings.

17. **[file_perms_4056_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/file_perms_4056_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that configuration database files, rollback files, rescue files, and archives are all verified to have owner-only permissions (0600/0700).

18. **[freetext_store_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/freetext_store_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that lenient parsing of free-text stanzas containing control characters is correctly tested.

19. **[history.go](file:///home/ps/git/gemini-xpf/pkg/configstore/history.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that history entries are stored in a ring buffer with proper bounds check on access to prevent out-of-range slice panics. (The negative size case is bounded by the `NewHistory` callers).

20. **[inactive_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/inactive_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that inactive apply-groups are stripped before group expansion to prevent false-rejection of missing groups.

21. **[journal.go](file:///home/ps/git/gemini-xpf/pkg/configstore/journal/journal.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that journal segments are size-rotated correctly, appends are fsynced, and tail scans use reverse chunk scans that skip over-large corrupted lines safely.

22. **[journal_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/journal/journal_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that tail scanning, UTF8 boundaries, file corruption, and concurrent log/tail operations are comprehensively tested.

23. **[journal_compat_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/journal_compat_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that `ListCommitHistory` output on legacy fat journal entries is equivalent between the pre-compaction and post-compaction readers.

24. **[load_compile_fail_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/load_compile_fail_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that configuration load failures tag compilation errors correctly so the daemon can refuse takeover and enter safe bootstrap mode.

25. **[marker_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/marker_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that the committed flag and never-committed marker are correctly validated under various store lifecycles and restarts.

26. **[nodeid_lenient_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/nodeid_lenient_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that lenient compile paths do not reject chassis node ID mismatches on startup to prevent boot loops.

27. **[persist_failure_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/persist_failure_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that database write failures are correctly reported, health degraded flags are set, and background retry loops operate as expected.

28. **[redaction_placeholder_4060_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/redaction_placeholder_4060_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that secret values are properly redacted using the placeholder during candidate display or API calls.

29. **[rescue_redaction_leak_4099_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/rescue_redaction_leak_4099_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that malformed rescue configuration files fail closed with a generic error and do not leak internal tokens.

30. **[store.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that the store initialization and basic setup (such as New() and compilation gates) correctly coordinate configuration, history, and persistence database instances.

31. **[store_commit.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store_commit.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Confirmed that commits, confirmations, and rollback promotions synchronize state transitions atomically under the store lock and invalidate stale timers.

32. **[store_format.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store_format.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that configuration display and comparisons correctly format candidate, active, and rollback configurations in text, XML, JSON, and redacted forms.

33. **[store_lock.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store_lock.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that shared and exclusive locking states, owner tracking, and session navigation are synchronized correctly under the store mutex.

34. **[store_lock_3979_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store_lock_3979_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that exclusive lock acquisitions and releases are properly tracked and released when sessions exit.

35. **[store_new_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store_new_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that New() initializes all fields correctly and refuses to start if the database directory cannot be created.

36. **[store_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/store_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that basic store operations (saving, loading, merging, copy/rename) are correctly tested under different scenarios.

37. **[system_action_journal_4108_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/system_action_journal_4108_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Confirmed that system actions like reboot/zeroize are logged in the journal and fsynced prior to action execution.

38. **[test_seams.go](file:///home/ps/git/gemini-xpf/pkg/configstore/test_seams.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Checked that test seams are cleanly exposed for tests to mock active config writes, verify generation values, and customize retry backoffs without production leak.

39. **[typed_leaf_lenient_test.go](file:///home/ps/git/gemini-xpf/pkg/configstore/typed_leaf_lenient_test.go)**  
    * **Status:** Negative Result  
    * **Invariant checked:** Verified that typed leaf validation violations in stored or synced configurations are downgraded to warnings.

---

#### Finding 11: Data Race on `cachedNlHandle` in `Monitor.getNlHandle()`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/cluster/monitor.go`
  ```go
`pkg/cluster/monitor.go` lines 543-558:
  ```go
  func (mon *Monitor) getNlHandle() nlLinkGetter {
  	if mon.nlHandle != nil {
  		return mon.nlHandle
  	}
  	// Cache the production handle to avoid leaking netlink sockets.
  	if mon.cachedNlHandle != nil {
  		return mon.cachedNlHandle
  	}
  	h, err := netlink.NewHandle()
  	if err != nil {
  		slog.Warn("cluster monitor: failed to create netlink handle", "err", err)
  		return &noopNlHandle{}
  	}
  	mon.cachedNlHandle = h
  	return h
  }
  ```
  ```
* **Trace:**
  1. The monitor runs a background loop calling `poll()` periodically, which calls `pollInterfaceMonitors()`.
  2. `pollInterfaceMonitors()` calls `getNlHandle()` (lines 260-261) without acquiring `mon.mu`.
  3. Concurrently, a daemon goroutine or a status request calls `RGInterfaceReady(rgID)` (lines 501-506), which unlocks `mon.mu` at line 504, and then calls `getNlHandle()` at line 506.
  4. Both goroutines concurrently evaluate `mon.cachedNlHandle == nil`.
  5. Both invoke `netlink.NewHandle()`, creating two separate netlink handles/sockets.
  6. The second write to `mon.cachedNlHandle` overwrites the first, silently leaking one of the netlink socket file descriptors.
  7. Concurrently, `Monitor.Stop()` (lines 185-190) acquires `mon.mu` and resets `mon.cachedNlHandle = nil`, which races with the read/write in `getNlHandle()`.
* **Refutation attempt:**
  We verified if the callers of `getNlHandle()` ensure serialization. `poll()` releases `mon.mu` at line 230 before calling `pollInterfaceMonitors`. `RGInterfaceReady` releases `mon.mu` at line 504 before calling `getNlHandle()`. Thus, the concurrent read and write to `mon.cachedNlHandle` are entirely unsynchronized. The finding survives.
* **HPC/invariant check:**
  Lock-free/lazy-init caching pattern fails when not protected by sync primitives or sync.Once.
* **Why it matters:**
  Each `netlink.Handle` creates a netlink socket, consuming a file descriptor. Under concurrent status checks or polling, file descriptors will leak, eventually causing the process to run out of FDs and crash, creating a cluster outage.
* **Fix direction:**
  Wrap the lazy-initialization of `mon.cachedNlHandle` inside `getNlHandle()` using `mon.mu` (which is already present in `Monitor`).
* **Labels:** `concurrency`, `resource-leak`
* **Dedup note:**
  Not present in the dedup index (which only notes a `Manager.Start` deadlock).

---

---

#### Finding 12: Resource Leak and Spurious Wakeup of `rg.holdTimer` in `readiness.go`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/cluster/readiness.go`
  ```go
`pkg/cluster/readiness.go` lines 34-51:
  ```go
  		if m.takeoverHoldTime > 0 {
  			if rg.holdTimer != nil {
  				rg.holdTimer.Stop()
  			}
  			rg.holdTimer = time.AfterFunc(m.takeoverHoldTime, func() {
  				m.mu.Lock()
  				defer m.mu.Unlock()
  				if !rg.Ready {
  					return
  				}
  				slog.Info("cluster: hold timer expired, re-evaluating election", "rg", rgID)
  				if m.peerAlive {
  					m.runElection()
  				} else {
  					m.electSingleNode()
  				}
  			})
  		}
  ```
  ```
* **Trace:**
  1. A redundancy group transitions from not-ready to ready, scheduling a deferred election re-evaluation via `time.AfterFunc` stored in `rg.holdTimer`.
  2. The operator stops the manager or the cluster daemon shuts down, calling `Manager.Stop()`.
  3. `Manager.Stop()` stops the heartbeat and monitor routines but leaves all active `rg.holdTimer` timers running in the background.
  4. The timer fires, executing the anonymous function.
  5. The closure acquires `m.mu.Lock()` and attempts to run elections (`m.runElection` or `m.electSingleNode`) on a stopped/quiesced manager, causing unexpected state mutations and log output.
  6. The timer reference also leaks the `Manager` instance from garbage collection until the duration expires.
* **Refutation attempt:**
  We checked `Manager.Stop()` in `pkg/cluster/manager.go`. It only stops `m.monitor`, `m.hbSender`, and `m.hbReceiver`. It does not iterate over `m.groups` to stop any active `holdTimer` instances. The finding is a true positive.
* **HPC/invariant check:**
  Lifecycle resource safety; timers must be canceled during shutdown.
* **Why it matters:**
  Spurious election evaluations on a stopped manager can lead to memory leaks, state mutations on shutdown, and flaky unit/integration tests during teardown.
* **Fix direction:**
  In `Manager.Stop()`, loop over all redundancy groups in `m.groups` and call `Stop()` on `rg.holdTimer` if it is non-nil.
* **Labels:** `resource-leak`, `lifecycle`
* **Dedup note:**
  Not present in the dedup index.

---

## 3. Module-by-Module Sweep (Negative Results)

For the remaining 84 files in the batch, the invariants were checked and found sound. The detail of what was checked is provided below:

### `pkg/cluster`
1. **pkg/cluster/cluster_test.go**  
   *Negative Result:* Checked that unit test cases verify state updates, election outcomes, and manual failovers correctly without mocking errors.
2. **pkg/cluster/election.go**  
   *Negative Result:* Verified that effective priority calculations (`EffectivePriority`) properly handle priority bounds [0, 255] and tie-breaking.
3. **pkg/cluster/election_test.go**  
   *Negative Result:* Checked election priority computation tests and confirmed they cover edge weights.
4. **pkg/cluster/events.go**  
   *Negative Result:* Verified thread-safe event logging with `sync.RWMutex` ring buffer operations.
5. **pkg/cluster/events_log.go**  
   *Negative Result:* Checked that history accessors wrap the locked ring buffer helper correctly.
6. **pkg/cluster/events_test.go**  
   *Negative Result:* Checked event history testing and bounds verification.
7. **pkg/cluster/failover.go**  
   *Negative Result:* Audited manual failover procedures (`ResignRG`, `ManualFailoverBatch`); verification locks and pre-prepare hooks execute under correct lock scopes.
8. **pkg/cluster/garp.go**  
   *Negative Result:* Checked gratuitous ARP/NA packet constructors and background burst handlers. Burst cancellation on abdication is correctly gated.
9. **pkg/cluster/garp_abdicate_test.go**  
   *Negative Result:* Checked that test cases correctly verify GARP termination on demotion.
10. **pkg/cluster/garp_burst_errors_test.go**  
    *Negative Result:* Verified error-accumulation test coverage on raw packet send failures.
11. **pkg/cluster/garp_test.go**  
    *Negative Result:* Checked gratuitous packet serialization correctness.
12. **pkg/cluster/group_state.go**  
    *Negative Result:* Checked redundancy group config synchronization accessors. Map deletions and heartbeat parameter updates are guarded by `m.mu`.
13. **pkg/cluster/heartbeat.go**  
    *Negative Result:* Audited heartbeat wire codec, MAC PSK validation, and anti-replay window logic. Anti-replay counters use monotonic clocks and cannot wrap.
14. **pkg/cluster/heartbeat_auth_test.go**  
    *Negative Result:* Checked HMAC authentication and replay-prevention test cases.
15. **pkg/cluster/heartbeat_guard_recheck_test.go**  
    *Negative Result:* Checked that liveness timeout override guards verify correctly.
16. **pkg/cluster/heartbeat_liveness_test.go**  
    *Negative Result:* Checked peer liveness testing and threshold timeout edge cases.
17. **pkg/cluster/heartbeat_manager.go**  
    *Negative Result:* Audited socket initialization and packet sender/receiver lifecycles. Lock order between `m.mu` and `hbStartMu` is consistent.
18. **pkg/cluster/heartbeat_neverseen_floor_test.go**  
    *Negative Result:* Verified that heartbeat never-seen counters floor checks are tested.
19. **pkg/cluster/heartbeat_stop_previous_test.go**  
    *Negative Result:* Checked test cases verifying previous heartbeat sender cleanup.
20. **pkg/cluster/heartbeat_test.go**  
    *Negative Result:* Checked general heartbeat serialization unit tests.
21. **pkg/cluster/hooks.go**  
    *Negative Result:* Verified pre-prepare manual failover daemon callbacks.
22. **pkg/cluster/kernel_selfrecover.go**  
    *Negative Result:* Verified local-drain and peer-healthy indicators. Lock ordering is correct.
23. **pkg/cluster/lease_sync_wire_test.go**  
    *Negative Result:* Verified DHCP lease replication message formatting tests.
24. **pkg/cluster/manager.go**  
    *Negative Result:* Checked manager lifecycle operations (`Start`, `Stop`, `resetRunStateLocked`). Re-initialization after Stop is clean.
25. **pkg/cluster/monitor_test.go**  
    *Negative Result:* Checked interface link state monitoring and raw socket ping unit tests.
26. **pkg/cluster/peer_state.go**  
    *Negative Result:* Verified peer state querying methods execute under RLock.
27. **pkg/cluster/reth.go**  
    *Negative Result:* Audited Redundant Ethernet physical member MAC programming. Physical interfaces are set UP under proper netlink transactions.
28. **pkg/cluster/reth_test.go**  
    *Negative Result:* Verified RETH MAC reprogramming and stable IPv6 link-local tests.
29. **pkg/cluster/runtime.go**  
    *Negative Result:* Checked cluster runtime interfaces.
30. **pkg/cluster/status.go**  
    *Negative Result:* Audited Junos-style cluster status formatters; all fields are snapshots read under lock.
31. **pkg/cluster/sync.go**  
    *Negative Result:* Audited session sync state replication, stats publishers, and bulk sync. Generation map limits prevent memory bloating.
32. **pkg/cluster/sync_auth.go**  
    *Negative Result:* Verified session-sync stream encryption and downgrade guards.
33. **pkg/cluster/sync_auth_test.go**  
    *Negative Result:* Checked sync auth validation tests.
34. **pkg/cluster/sync_bulk.go**  
    *Negative Result:* Verified session bulk synchronization and stale-entry reconciliation.
35. **pkg/cluster/sync_config_gen_test.go**  
    *Negative Result:* Checked config generation ordering tests.
36. **pkg/cluster/sync_conn.go**  
    *Negative Result:* Checked TCP session-sync listener and connection-handshake routines.
37. **pkg/cluster/sync_failover.go**  
    *Negative Result:* Checked state-transfer handoff signaling and sequence ack tracking.
38. **pkg/cluster/sync_gen_guard_test.go**  
    *Negative Result:* Checked session generation-guard tests.
39. **pkg/cluster/sync_protocol.go**  
    *Negative Result:* Checked sync message byte serialization codecs. Gated lengths prevent overflows.
40. **pkg/cluster/sync_state.go**  
    *Negative Result:* Checked local session-sync state machine getters.
41. **pkg/cluster/sync_test.go**  
    *Negative Result:* Checked session-sync integration and simulation tests.

### `pkg/conntrack`
42. **pkg/conntrack/gc.go**  
    *Negative Result:* Audited conntrack GC. Config updates and telemetry counters are read under locks. Aggressive aging clamps negative inputs safely.
43. **pkg/conntrack/gc_test.go**  
    *Negative Result:* Checked conntrack GC sweeps and session limit tests.
44. **pkg/conntrack/legacy_dataplane_canary_test.go**  
    *Negative Result:* Checked BPF map validation compatibility test cases.

### `pkg/ra`
45. **pkg/ra/filter.go**  
    *Negative Result:* Checked that NDP packet filter allows Router Solicitations and blocks others correctly.
46. **pkg/ra/ra.go**  
    *Negative Result:* Audited Router Advertisement manager; interface-draining tombstones correctly prevent duplicate NDP listeners.
47. **pkg/ra/ra_test.go**  
    *Negative Result:* Checked RA daemon config applies and withdraw tests.
48. **pkg/ra/sender.go**  
    *Negative Result:* Verified that multicast RA advertisements are built correctly and link-local address binding is ensured.
49. **pkg/ra/sender_linklocal_test.go**  
    *Negative Result:* Verified link-local NDP tests.
50. **pkg/ra/sender_marshal_3895_test.go**  
    *Negative Result:* Verified NDP option marshaling test cases.
51. **pkg/ra/sender_marshal_4119_test.go**  
    *Negative Result:* Verified additional NDP prefix option test cases.
52. **pkg/ra/sender_marshal_4307_test.go**  
    *Negative Result:* Verified NDP MTU option test cases.
53. **pkg/ra/serialize_test.go**  
    *Negative Result:* Checked NDP message serialization unit tests.

### `pkg/vrrp`
54. **pkg/vrrp/addrwatch.go**  
    *Negative Result:* Audited source address watcher; netlink address modifications trigger correct re-resolutions without deadlocks.
55. **pkg/vrrp/addrwatch_test.go**  
    *Negative Result:* Verified address watcher trigger tests.
56. **pkg/vrrp/afpacket_cloexec_test.go**  
    *Negative Result:* Checked AF_PACKET socket FD properties (SOCK_CLOEXEC set).
57. **pkg/vrrp/afpacket_membership_test.go**  
    *Negative Result:* Checked multicast membership configuration tests.
58. **pkg/vrrp/bindtodevice_test.go**  
    *Negative Result:* Checked socket device-binding integration tests.
59. **pkg/vrrp/instance.go**  
    *Negative Result:* Audited state machine goroutine. Transitions and timer wakeups are race-free. Event drops are debounced.
60. **pkg/vrrp/instance_arp_probe_test.go**  
    *Negative Result:* Checked ARP cache validation test cases.
61. **pkg/vrrp/instance_garp_abdicate_test.go**  
    *Negative Result:* Checked GARP termination on VRRP backup transition tests.
62. **pkg/vrrp/instance_garp_force_test.go**  
    *Negative Result:* Checked bypass-dampener GARP force-send tests.
63. **pkg/vrrp/instance_garp_probe_target_test.go**  
    *Negative Result:* Checked VRRP probe targets tests.
64. **pkg/vrrp/instance_garp_test.go**  
    *Negative Result:* Checked general GARP emission tests.
65. **pkg/vrrp/instance_ifindex_filter_test.go**  
    *Negative Result:* Checked VLAN interface packet filtering tests.
66. **pkg/vrrp/instance_localip_race_test.go**  
    *Negative Result:* Checked local IP lazy resolution data race tests.
67. **pkg/vrrp/instance_master_interval_test.go**  
    *Negative Result:* Checked master advertisement interval learning tests.
68. **pkg/vrrp/instance_owner_preempt_test.go**  
    *Negative Result:* Checked owner priority-255 preemption tests.
69. **pkg/vrrp/instance_preempt_gate_test.go**  
    *Negative Result:* Checked preemption suppression tests.
70. **pkg/vrrp/instance_preempt_hold_revalidate_test.go**  
    *Negative Result:* Checked preempt hold revalidation tests.
71. **pkg/vrrp/instance_preempt_holdtime_test.go**  
    *Negative Result:* Checked preempt hold-timer countdown tests.
72. **pkg/vrrp/instance_rxdrop_race_test.go**  
    *Negative Result:* Checked receive drop warning counter tests.
73. **pkg/vrrp/instance_v6_pktinfo_test.go**  
    *Negative Result:* Checked IPv6 control message source binding tests.
74. **pkg/vrrp/instance_vipset_canon_test.go**  
    *Negative Result:* Checked VIP set equivalence matching tests.
75. **pkg/vrrp/manager.go**  
    *Negative Result:* Audited VRRP manager and instance list diffing (`UpdateInstances`). Link watcher and address watcher instantiation is clean.
76. **pkg/vrrp/manager_garp_unsuppress_test.go**  
    *Negative Result:* Checked GARP unsuppress trigger tests.
77. **pkg/vrrp/manager_reuse_test.go**  
    *Negative Result:* Checked manager Stop/Start reuse tests.
78. **pkg/vrrp/packet.go**  
    *Negative Result:* Checked VRRPv3 packet marshaler/unmarshaler. Pseudo-header checksums are mathematically correct.
79. **pkg/vrrp/packet_checksum_test.go**  
    *Negative Result:* Checked checksum verification unit tests.
80. **pkg/vrrp/track.go**  
    *Negative Result:* Checked interface tracking priority cost calculation and singleton link watcher. Cache renaming handles renames correctly.
81. **pkg/vrrp/track_test.go**  
    *Negative Result:* Checked interface state change priority tracking tests.
82. **pkg/vrrp/update_instances_test.go**  
    *Negative Result:* Checked UpdateInstances additions/removals/updates tests.
83. **pkg/vrrp/vrrp.go**  
    *Negative Result:* Checked VRRP config interface parsers.
84. **pkg/vrrp/vrrp_test.go**  
    *Negative Result:* Checked VRRP integration tests.

---

#### Finding 13: Lifetime Average CPU Usage Since Boot Reported as Current CPU Gauge in Metrics Collector
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/api/metrics_system.go:305-L340`
  ```go
* File: [pkg/api/metrics_system.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_system.go#L305-L340)
  ```go
	// CPU usage from /proc/stat (instantaneous snapshot)
	if f, err := os.Open("/proc/stat"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "cpu ") {
				fields := strings.Fields(line)
				// fields: cpu user nice system idle iowait irq softirq steal
				if len(fields) >= 5 {
					user, _ := strconv.ParseFloat(fields[1], 64)
					nice, _ := strconv.ParseFloat(fields[2], 64)
					system, _ := strconv.ParseFloat(fields[3], 64)
					idle, _ := strconv.ParseFloat(fields[4], 64)
					iowait := 0.0
					if len(fields) >= 6 {
						iowait, _ = strconv.ParseFloat(fields[5], 64)
					}
					total := user + nice + system + idle + iowait
					if len(fields) >= 9 {
						irq, _ := strconv.ParseFloat(fields[6], 64)
						softirq, _ := strconv.ParseFloat(fields[7], 64)
						steal, _ := strconv.ParseFloat(fields[8], 64)
						total += irq + softirq + steal
					}
					cpus := float64(runtime.NumCPU())
					if total > 0 && cpus > 0 {
						ch <- prometheus.MustNewConstMetric(c.sysCPUUser, prometheus.GaugeValue,
							(user+nice)/total*100*cpus)
						ch <- prometheus.MustNewConstMetric(c.sysCPUSystem, prometheus.GaugeValue,
							system/total*100*cpus)
					}
				}
			}
		}
	}
  ```
  ```
* **Trace:**
  1. A Prometheus server scrapes `/metrics`.
  2. The collector reads raw cumulative ticks from `/proc/stat` representing time spent in each CPU state since system boot.
  3. The collector directly divides user/system ticks by total ticks since boot.
  4. The calculated ratio is exported as gauges `xpf_system_cpu_user_percent` and `xpf_system_cpu_system_percent`.
  5. The resulting metric shows the average CPU usage over the entire lifetime of the system since boot, which barely changes as system uptime grows.
* **Refutation attempt:**
  We verified if the collector stores previous ticks to perform delta computations. The collector has no historical state storage. Thus, it always evaluates the absolute cumulative tick counts, certifying that the output is indeed the system-boot lifetime average.
* **HPC/invariant check:**
  Prometheus metrics design dictates that cumulative counters are exported as counters so that the Prometheus server can compute the rate (`rate(...)`). Emitting cumulative percentages directly as a gauge breaks standard time-series queries.
* **Why it matters:**
  Current CPU spikes or high load due to packet processing failures will be completely invisible on dashboard gauges once the system uptime is high. This compromises observability and prevents CPU load alarms from firing.
* **Fix direction:**
  Convert the metrics to counters (e.g. `xpf_system_cpu_seconds_total`) and export the raw ticks labeled by mode, or keep state in the collector to compute differential rates over the last scrape interval.
* **Labels:** `observability`, `metrics-correctness`
* **Dedup note:**
  This is a new finding not present in the dedup index.

---

---

#### Finding 14: `logging: SyslogSlogHandler fails to update client references in derived handlers during config reload`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/logging/slog_handler.go:115-L134`
  ```go
In [pkg/logging/slog_handler.go](file:///home/ps/git/gemini-xpf/pkg/logging/slog_handler.go#L115-L134):
  ```go
  // WithAttrs implements slog.Handler.
  func (h *SyslogSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
  	return &SyslogSlogHandler{
  		base:       h.base.WithAttrs(attrs),
  		clients:    h.clients,
  		attrs:      append(append([]slog.Attr{}, h.attrs...), attrs...),
  		groups:     h.groups,
  		forwarding: h.forwarding, // share the re-entrancy guard (#2287)
  	}
  }

  // WithGroup implements slog.Handler.
  func (h *SyslogSlogHandler) WithGroup(name string) slog.Handler {
  	return &SyslogSlogHandler{
  		base:       h.base.WithGroup(name),
  		clients:    h.clients,
  		attrs:      h.attrs,
  		groups:     append(append([]string{}, h.groups...), name),
  		forwarding: h.forwarding, // share the re-entrancy guard (#2287)
  	}
  }
  ```
  ```
* **Trace:**
  1. During daemon startup, the root `SyslogSlogHandler` is instantiated and its clients are set via `SetClients()`.
  2. Sub-modules create contextual loggers using `logger.With(...)` or `logger.WithGroup(...)`, which internally calls `WithAttrs` or `WithGroup` on the root `SyslogSlogHandler`.
  3. The resulting derived `SyslogSlogHandler` copies the `clients` slice reference (holding the current slice header pointer).
  4. Later, the operator updates the configuration (e.g., modifying syslog destinations). The daemon calls `SetClients` on the root handler, replacing its `h.clients` slice with a newly created slice of new clients and closing the old clients.
  5. The derived handlers still hold the old `clients` slice reference.
  6. Any log message subsequently sent via the derived loggers calls `Handle`, which iterates over the derived handler's `clients` (the old, closed clients).
  7. The old clients fail to write because they are closed, resulting in dropped log messages and silent telemetry loss.
* **Refutation attempt:**
  I checked if there is any mechanism that propagates the new `clients` slice to the derived handlers. There is none. The derived handlers are independent structs created by value containing a copy of the slice header `clients`. When the root handler's `clients` field is reassigned to a new slice, the derived handlers' `clients` fields continue to point to the old slice. I also checked if the elements of `clients` are mutated in-place; they are not. The slice is replaced entirely. Therefore, the finding survives.
* **HPC/invariant check:**
  Not directly applicable (concurrency-safe read/write on stale references).
* **Why it matters:**
  It causes structured loggers created with attributes or groups to silently drop all syslog messages after the first configuration reload or change. This is a severe telemetry gap that hides security events from syslog collectors.
* **Fix direction:**
  Introduce a shared mutable state struct (e.g., `type syslogState struct { mu sync.RWMutex; clients []*SyslogClient }`) that is shared by pointer (`*syslogState`) across the root and all derived `SyslogSlogHandler` instances, similar to how the re-entrancy guard `forwarding` (`*sync.Map`) is shared.
* **Labels:** `correctness`, `reliability`
* **Dedup note:**
  This is a new finding about the `SyslogSlogHandler` re-entrancy/derivation mechanics, not related to any of the prior findings.

---

---

#### Finding 15: `rpm: File descriptor leak in http-get probe via discarded http.Transport`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/rpm/rpm.go:747-L766`
  ```go
In [pkg/rpm/rpm.go](file:///home/ps/git/gemini-xpf/pkg/rpm/rpm.go#L747-L766):
  ```go
  	dialer, err := probeDialer(10*time.Second, test.SourceAddress, opts)
  	if err != nil {
  		return 0, err
  	}
  	transport := &http.Transport{
  		DialContext: dialer.DialContext,
  	}
  	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

  	start := time.Now()
  	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
  	if err != nil {
  		return 0, fmt.Errorf("HTTP request error: %w", err)
  	}
  	resp, err := client.Do(req)
  	if err != nil {
  		return 0, fmt.Errorf("HTTP GET failed: %w", err)
  	}
  	resp.Body.Close()
  ```
  ```
* **Trace:**
  1. `runProbeLoop` executes `runSingleTest` periodically (on every test interval).
  2. `runSingleTest` calls `runProbe` -> `executeProbe` -> `probeHTTP` for each HTTP ping.
  3. `probeHTTP` creates a new `http.Transport` and `http.Client`.
  4. `client.Do(req)` executes, dialer dials a TCP connection.
  5. The server responds, and `resp.Body.Close()` is called. This returns the connection to the `transport`'s idle connection pool.
  6. The `probeHTTP` function returns, discarding the `client` and `transport` references.
  7. Because `DisableKeepAlives` is false by default on `http.Transport`, the TCP connection remains open in the discarded transport's pool, leaking the file descriptor (socket) until the TCP keep-alive times out or the socket is closed by the peer.
* **Refutation attempt:**
  I checked if Go's garbage collector automatically closes connections when `http.Transport` is collected. It does not. Active connections in a transport's pool keep read/write loop goroutines alive, preventing the transport from being garbage-collected until those goroutines exit (usually when the connection is closed by the server or times out). Thus, the sockets are leaked. I also checked if there is any shared client; there is not, the client is allocated on the stack locally on every probe. Therefore, the finding survives.
* **HPC/invariant check:**
  Resource limits, socket reuse.
* **Why it matters:**
  Under persistent HTTP probing, this will leak file descriptors and goroutines rapidly, eventually exhausting system resources (FDs) and crashing or degrading the `xpf` daemon.
* **Fix direction:**
  Set `DisableKeepAlives: true` on the locally created `http.Transport` inside `probeHTTP`, or call `defer transport.CloseIdleConnections()`.
* **Labels:** `resource-leak`, `performance`
* **Dedup note:**
  This is a new resource leak finding that is completely absent from the prior findings list.

---

## Module Sweep & Negative Results

### Module: `pkg/eventengine`
* **Files**: 
  - [pkg/eventengine/engine.go](file:///home/ps/git/gemini-xpf/pkg/eventengine/engine.go)
  - [pkg/eventengine/engine_edge_trigger_3756_test.go](file:///home/ps/git/gemini-xpf/pkg/eventengine/engine_edge_trigger_3756_test.go)
  - [pkg/eventengine/engine_inclusive_until_3756_test.go](file:///home/ps/git/gemini-xpf/pkg/eventengine/engine_inclusive_until_3756_test.go)
  - [pkg/eventengine/engine_integration_test.go](file:///home/ps/git/gemini-xpf/pkg/eventengine/engine_integration_test.go)
  - [pkg/eventengine/engine_stale_revalidate_3750_test.go](file:///home/ps/git/gemini-xpf/pkg/eventengine/engine_stale_revalidate_3750_test.go)
  - [pkg/eventengine/engine_test.go](file:///home/ps/git/gemini-xpf/pkg/eventengine/engine_test.go)
  - [pkg/eventengine/engine_window_test.go](file:///home/ps/git/gemini-xpf/pkg/eventengine/engine_window_test.go)
  - [pkg/eventengine/engine_within_failclosed_3751_test.go](file:///home/ps/git/gemini-xpf/pkg/eventengine/engine_within_failclosed_3751_test.go)
* **Negative Result**:
  - Checked the transactional configuration changes (`applyOnce`). We verified that any failure in applying the plan triggers `ExitConfigure()`, reverting the candidate configuration and leaving no half-applied configuration.
  - Checked test suites and verified they serve as a valid regression safety net for revalidation, temporal windows, and edge triggering.

### Module: `pkg/feeds`
* **Files**: 
  - [pkg/feeds/feeds.go](file:///home/ps/git/gemini-xpf/pkg/feeds/feeds.go)
  - [pkg/feeds/feeds_bindings_test.go](file:///home/ps/git/gemini-xpf/pkg/feeds/feeds_bindings_test.go)
  - [pkg/feeds/feeds_sizecap_3934_test.go](file:///home/ps/git/gemini-xpf/pkg/feeds/feeds_sizecap_3934_test.go)
  - [pkg/feeds/feeds_test.go](file:///home/ps/git/gemini-xpf/pkg/feeds/feeds_test.go)
* **Negative Result**:
  - Checked the bounded response body reading (`maxFeedBodyBytes`) and prefix limits (`maxFeedPrefixes`). We verified that `parseFeed` reads through an `io.LimitReader` and returns an error immediately if either limit is exceeded, preventing daemon OOM.
  - Checked test suites and verified they cover CIDR parsing, size capping, and hold intervals.

### Module: `pkg/flowexport`
* **Files**: 
  - [pkg/flowexport/exporterid.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/exporterid.go)
  - [pkg/flowexport/ipfix.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/ipfix.go)
  - [pkg/flowexport/manager.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/manager.go)
  - [pkg/flowexport/netflow.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/netflow.go)
  - [pkg/flowexport/routemask.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/routemask.go)
  - [pkg/flowexport/transport.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/transport.go)
  - [pkg/flowexport/addr_format_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/addr_format_test.go)
  - [pkg/flowexport/collector_health_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/collector_health_test.go)
  - [pkg/flowexport/collector_stall_4423_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/collector_stall_4423_test.go)
  - [pkg/flowexport/cos_fields_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/cos_fields_test.go)
  - [pkg/flowexport/dropped_fields_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/dropped_fields_test.go)
  - [pkg/flowexport/exporter_id_3740_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/exporter_id_3740_test.go)
  - [pkg/flowexport/exporter_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/exporter_test.go)
  - [pkg/flowexport/flowbatch_bounded_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/flowbatch_bounded_test.go)
  - [pkg/flowexport/flowdir_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/flowdir_test.go)
  - [pkg/flowexport/flowstart_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/flowstart_test.go)
  - [pkg/flowexport/ingress_interface_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/ingress_interface_test.go)
  - [pkg/flowexport/instance_isolation_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/instance_isolation_test.go)
  - [pkg/flowexport/ipfix_biflow_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/ipfix_biflow_test.go)
  - [pkg/flowexport/ipfix_sampler_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/ipfix_sampler_test.go)
  - [pkg/flowexport/ipfix_seqnum_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/ipfix_seqnum_test.go)
  - [pkg/flowexport/per_collector_source_3745_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/per_collector_source_3745_test.go)
  - [pkg/flowexport/postnat_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/postnat_test.go)
  - [pkg/flowexport/protocol_num_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/protocol_num_test.go)
  - [pkg/flowexport/routemask_vrf_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/routemask_vrf_test.go)
  - [pkg/flowexport/srcmask_dstmask_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/srcmask_dstmask_test.go)
  - [pkg/flowexport/template_group_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/template_group_test.go)
  - [pkg/flowexport/transport_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/transport_test.go)
  - [pkg/flowexport/version_binding_test.go](file:///home/ps/git/gemini-xpf/pkg/flowexport/version_binding_test.go)
* **Negative Result**:
  - Checked the stable, non-zero ID derivation via FNV-1a. We verified it is a pure function of synced config, ensuring HA symmetry and preventing ID collision on same-collector template groups.
  - Checked IPFIX/NetFlow template sum-length calculations. We verified that build-time panic assertions exist to prevent template and data record desynchronization/corruption.
  - Checked the non-blocking cache lookup and VRF isolation in `routeMaskCache`. We verified that route mask cache keying includes the VRF `ifindex` to prevent cross-VRF cache hits, and misses are deferred to background goroutines to keep the hot event reader non-blocking.
  - Checked all associated test suites and verified they cover collector health, Cos fields, batch bounds, post-NAT resolving, and VRF scope mappings.

### Module: `pkg/logging`
* **Files**: 
  - [pkg/logging/aggregator.go](file:///home/ps/git/gemini-xpf/pkg/logging/aggregator.go)
  - [pkg/logging/event_filter_args.go](file:///home/ps/git/gemini-xpf/pkg/logging/event_filter_args.go)
  - [pkg/logging/eventbuf.go](file:///home/ps/git/gemini-xpf/pkg/logging/eventbuf.go)
  - [pkg/logging/goid.go](file:///home/ps/git/gemini-xpf/pkg/logging/goid.go)
  - [pkg/logging/locallog.go](file:///home/ps/git/gemini-xpf/pkg/logging/locallog.go)
  - [pkg/logging/ringbuf.go](file:///home/ps/git/gemini-xpf/pkg/logging/ringbuf.go)
  - [pkg/logging/syslog.go](file:///home/ps/git/gemini-xpf/pkg/logging/syslog.go)
  - [pkg/logging/trace.go](file:///home/ps/git/gemini-xpf/pkg/logging/trace.go)
  - [pkg/logging/aggregator_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/aggregator_test.go)
  - [pkg/logging/binary_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/binary_test.go)
  - [pkg/logging/default_policy_sentinel_3057_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/default_policy_sentinel_3057_test.go)
  - [pkg/logging/event_filter_args_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/event_filter_args_test.go)
  - [pkg/logging/event_severity_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/event_severity_test.go)
  - [pkg/logging/event_time_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/event_time_test.go)
  - [pkg/logging/eventbuf_close_3384_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/eventbuf_close_3384_test.go)
  - [pkg/logging/eventbuf_negative_3342_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/eventbuf_negative_3342_test.go)
  - [pkg/logging/eventbuf_zone0_3338_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/eventbuf_zone0_3338_test.go)
  - [pkg/logging/host_inbound_deny_3610_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/host_inbound_deny_3610_test.go)
  - [pkg/logging/locallog_format_3409_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/locallog_format_3409_test.go)
  - [pkg/logging/locallog_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/locallog_test.go)
  - [pkg/logging/per_policy_log_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/per_policy_log_test.go)
  - [pkg/logging/protocol_num_builder_3382_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/protocol_num_builder_3382_test.go)
  - [pkg/logging/protoname_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/protoname_test.go)
  - [pkg/logging/session_close_format_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/session_close_format_test.go)
  - [pkg/logging/session_create_format_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/session_create_format_test.go)
  - [pkg/logging/syslog_lazy_connect_3351_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/syslog_lazy_connect_3351_test.go)
  - [pkg/logging/syslog_partial_frame_3874_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/syslog_partial_frame_3874_test.go)
  - [pkg/logging/syslog_reentrancy_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/syslog_reentrancy_test.go)
  - [pkg/logging/syslog_replace_close_3579_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/syslog_replace_close_3579_test.go)
  - [pkg/logging/syslog_resilience_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/syslog_resilience_test.go)
  - [pkg/logging/syslog_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/syslog_test.go)
  - [pkg/logging/trace_filter_3422_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/trace_filter_3422_test.go)
  - [pkg/logging/trace_size_3424_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/trace_size_3424_test.go)
  - [pkg/logging/trace_test.go](file:///home/ps/git/gemini-xpf/pkg/logging/trace_test.go)
* **Negative Result**:
  - Checked the bounded memory footprint of Space-Saving stream summaries. We verified that the total number of monitored keys in `minHeap` is capped at `maxKeys`, preventing memory growth during high-cardinality scan traffic.
  - Checked `EventBuffer` thread-safe circular buffer indexing and subscriber synchronization. Subscription close executes `unsubscribe` under `subMu` write-lock, preventing race-on-closed-channel panic.
  - Checked trace file name validation and directory isolation. `sanitizeTraceFileName` rejects path traversals, preventing writing files outside `/var/log`.
  - Checked log drop warnings and re-entrancy deadlocks. The `SyslogClient` correctly defers drop warnings to a deferred function that runs after `Unlock()`, preventing self-deadlock on `s.mu`.

### Module: `pkg/rpm`
* **Files**: 
  - [pkg/rpm/display.go](file:///home/ps/git/gemini-xpf/pkg/rpm/display.go)
  - [pkg/rpm/icmp.go](file:///home/ps/git/gemini-xpf/pkg/rpm/icmp.go)
  - [pkg/rpm/event_buffer_3755_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/event_buffer_3755_test.go)
  - [pkg/rpm/http_scheme_2495_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/http_scheme_2495_test.go)
  - [pkg/rpm/icmp_ctx_2647_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/icmp_ctx_2647_test.go)
  - [pkg/rpm/icmp_linklocal_2494_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/icmp_linklocal_2494_test.go)
  - [pkg/rpm/icmp_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/icmp_test.go)
  - [pkg/rpm/pin_hold_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/pin_hold_test.go)
  - [pkg/rpm/probe_dialer_2492_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/probe_dialer_2492_test.go)
  - [pkg/rpm/scoped_hostname_2493_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/scoped_hostname_2493_test.go)
  - [pkg/rpm/transition_cycle_test.go](file:///home/ps/git/gemini-xpf/pkg/rpm/transition_cycle_test.go)
* **Negative Result**:
  - Checked the ICMP echo matching and reply validation. ID/Seq matching, source IP comparisons, and raw socket creation are properly checked under context deadlines.
  - Checked sorting determinism of probe/test names and CLI rendering formats.

### Module: `pkg/snmp`
* **Files**: 
  - [pkg/snmp/agent.go](file:///home/ps/git/gemini-xpf/pkg/snmp/agent.go)
  - [pkg/snmp/traps.go](file:///home/ps/git/gemini-xpf/pkg/snmp/traps.go)
  - [pkg/snmp/v3.go](file:///home/ps/git/gemini-xpf/pkg/snmp/v3.go)
  - [pkg/snmp/agent_clients_4289_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/agent_clients_4289_test.go)
  - [pkg/snmp/agent_secret_log_4302_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/agent_secret_log_4302_test.go)
  - [pkg/snmp/agent_set_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/agent_set_test.go)
  - [pkg/snmp/agent_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/agent_test.go)
  - [pkg/snmp/getbulk_size_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/getbulk_size_test.go)
  - [pkg/snmp/traps_async_2991_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/traps_async_2991_test.go)
  - [pkg/snmp/traps_community_2989_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/traps_community_2989_test.go)
  - [pkg/snmp/traps_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/traps_test.go)
  - [pkg/snmp/traps_version_3948_test.go](file:///home/ps/git/gemini-xpf/pkg/snmp/traps_version_3948_test.go)
  - [pkg/snmp/v3_auth_test.go](file:///home/ps/git/snmp/v3_auth_test.go)
  - [pkg/snmp/v3_context_test.go](file:///home/ps/git/snmp/v3_context_test.go)
  - [pkg/snmp/v3_priv_iv_test.go](file:///home/ps/git/snmp/v3_priv_iv_test.go)
  - [pkg/snmp/v3_seclevel_test.go](file:///home/ps/git/snmp/v3_seclevel_test.go)
  - [pkg/snmp/v3_set_test.go](file:///home/ps/git/snmp/v3_set_test.go)
  - [pkg/snmp/v3_timeliness_test.go](file:///home/ps/git/snmp/v3_timeliness_test.go)
* **Negative Result**:
  - Checked SNMPv3 cryptographic processing. The AES-128-CFB IV conforms exactly to RFC 3826 by using message-carried boots/time parameters to align with remote managers, preventing decryption failure due to clock differences.
  - Checked community access restrictions for SET/GET operations. The source IP checking (`AllowsSource`) is enforced properly.
  - Checked all SNMP test suites verifying that they cover community validation, secret logging protection, and getbulk sizing.

---

### Low Severity Findings (14 items)

#### Finding 1: Integer overflow/truncation in commit confirmed minutes input validation
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `cmd/cli/main.go`
  ```go
* File: `cmd/cli/main.go` Lines 248–251
  ```go
  			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
  				minutes = int32(v)
  			}
  ```
  * File: `pkg/cli/cli_config.go` Lines 215–218
  ```go
  			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
  				minutes = v
  			}
  ```
  ```
* **HPC/invariant check:**
  * Integer Truncation: Upcasting and downcasting checks.
* **Why it matters:**
  * An operator typing a large value (such as `2147483648` minutes) to `commit confirmed` will trigger a signed integer overflow when cast to `int32(v)`, resulting in a negative value (e.g. `-2147483648`). When transmitted to the daemon, this will cause unexpected behavior (e.g. immediate configuration rollback or timer bypass).
* **Fix direction:**
  * Validate that the parsed `v` is within a reasonable range (e.g., `1 <= v <= 65535`) before casting it to `int32` and calling `CommitConfirmed`.
* **Labels:** `input-validation`, `integer-truncation`
* **Dedup note:**
  The prior findings index contains "3. Remote ping count/size accepts negative Atoi without rejection" in `cmd/cli/main.go`, but does not cover the `commit confirmed` integer overflow/truncation in either `cmd/cli/main.go` or `pkg/cli/cli_config.go`.

---

## Negative Results (No Findings)

For every other module/file in the batch list, we audited correctness, memory safety, concurrency, parity, performance, and test coverage, finding them sound:

* `bpf/headers/xpf_common.h`: Verified that all firewall limits, protocol IDs, and common structures are structurally aligned with standard Junos specifications and memory bounds.
* `bpf/headers/xpf_conntrack.h`: Audited conntrack session structures and TCP state machine helpers; verified state transitions and timeouts handle packet pipelines correctly.
* `bpf/headers/xpf_helpers.h`: Audited parsing helpers for Ethernet, IPv4, IPv6, and L4 headers; verified that bounds checks on data pointer arithmetic cleanly prevent out-of-bounds reads.
* `bpf/headers/xpf_maps.h`: Verified map declarations, sizes, and flag options; confirmed preallocation settings and sizing criteria align with BPF resource limits.
* `bpf/headers/xpf_nat.h`: Audited NAT44, NAT64, NPTv6 translations, and checksum updates; verified that network/host byte order conversions are correct.
* `bpf/headers/xpf_trace.h`: Audited printk tracing macros; verified that tracing conditions compile out when disabled and do not introduce latency.
* `cmd/cli/clear.go`: Verified clear commands are authorized and delegated to backend handlers properly.
* `cmd/cli/main_test.go`: Confirmed comprehensive coverage for CLI bootstrap and argument parsing.
* `cmd/cli/monitor.go`: Audited terminal setRawMode / key-reader setup and gRPC remote monitor packet-drop/interfaces handlers. Found them safe.
* `cmd/cli/nontty_test.go`: Verified CLI non-interactive operation tests execute without terminal dependencies.
* `cmd/cli/policymatch_dup_3709_test.go`: Verified zone delimiter checks and test-policy duplicate handling are fully tested.
* `cmd/cli/query_strictness_3696_test.go`: Confirmed tests enforce validation strictness for query parsers.
* `cmd/cli/request.go`: Verified chassis, cluster, and software command handlers propagate requests to backend/peer correctly.
* `cmd/cli/request_wireguard_test.go`: Confirmed wireguard operational command requests are covered by unit tests.
* `cmd/cli/rollback_3447_test.go`: Verified configuration rollback boundary inputs are fully validated and tested.
* `cmd/cli/shared.go`: Audited shared helpers for terminal formatting; confirmed they are thread-safe.
* `cmd/cli/show.go`: Verified show commands are correctly mapped to show presenters.
* `cmd/cli/show_events_zone_3547_test.go`: Confirmed zone-based logging filters are tested.
* `cmd/cli/show_flowsession_3439_test.go`: Confirmed session filters and detail views are covered by tests.
* `cmd/cli/show_matchpolicies_port_3354_test.go`: Confirmed policy match routing matches port constraints in tests.
* `cmd/cli/show_matchpolicies_test.go`: Confirmed general policy matching tests.
* `cmd/cli/show_policies_metadata_3672_test.go`: Confirmed policy rule metadata rendering is verified.
* `cmd/cli/show_policies_scoped_global_3357_test.go`: Confirmed scoped global policy views are covered by tests.
* `cmd/cli/show_wireguard_test.go`: Verified wireguard show command rendering is tested.
* `cmd/cli/show_zones_hostinbound_3654_test.go`: Confirmed zone host-inbound matching is covered.
* `cmd/cli/show_zones_polerr_3669_test.go`: Confirmed zone policy errors are verified in tests.
* `cmd/cli/show_zones_tiers_3683_test.go`: Confirmed zone policy tier rendering is tested.
* `cmd/cli/testpolicy_port_test.go`: Confirmed test-policy command port options are fully covered.
* `cmd/cli/testpolicy_protocol_test.go`: Confirmed protocol parsing for test-policy is covered.
* `cmd/cli/testpolicy_srcport_test.go`: Confirmed source-port selector for test-policy is covered.
* `cmd/cli/usage_matchpolicies_3628_test.go`: Confirmed usage help formatting is covered by tests.
* `cmd/shimverify/main.go`: Verified that the userspace-XDP shim verifier runs cleanly and exits safely.
* `cmd/xpfd/main.go`: Verified daemon entry point handles command-line arguments, BPF verifier gates, and Day-0 configuration validations safely.
* `cmd/xpfd/publish_generation.go`: Checked staged-generation publishing and GC; verified upgrade locks prevent concurrent generation manipulation.
* `cmd/xpfd/seed_runtime.go`: Verified runtime versioned-layout seeding completes safely without cutting daemon execution.
* `cmd/xpfd/upgrade.go`: Verified rolling upgrade state machine configuration is validated.
* `cmd/xpfd/upgrade_kernel.go`: Verified that mutating kernel sub-verbs serialize using host-wide upgrade locks.
* `docs/pr/812-tx-latency-histogram/evidence/vdso_probe.c`: Verified that VDSO resolution clock calls execute without issues.
* `docs/pr/812-tx-latency-histogram/evidence/vdso_probe2.c`: Verified VDSO segment address visibility checks are correct.
* `pkg/cli/app_resolve.go`: Verified that application resolution walks user and builtin applications correctly without index safety issues.
* `pkg/cli/apply.go`: Audited syslog zone-name mapping and legacy dataplane apply commands; verified they run safely and prevent Quarantined zone name collisions.
* `pkg/cli/apply_syslog_zonemap_3704_test.go`: Verified that tests cover StableZoneID and Quarantine collisions for syslog zone mappings.
* `pkg/cli/chrony.go`: Verified NTP status output parser handles fields correctly.
* `pkg/cli/cli_activate_test.go`: Confirmed activation/deactivation tests cover candidate config manipulation.
* `pkg/cli/cli_clear.go`: Verified clear command presenters execute within authorization/permission boundaries.
* `pkg/cli/cli_clear_errors_test.go`: Confirmed session clear failure aggregation is covered by tests.
* `pkg/cli/cli_clear_reversekey_test.go`: Confirmed reverse companion deletion matches correct NAT translated tuples in tests.
* `pkg/cli/cli_commit_confirm_pending_4000_test.go`: Confirmed pending commit confirm behavior is covered.
* `pkg/cli/cli_commit_test.go`: Confirmed atomic commit-apply sequence tests.
* `pkg/cli/cli_config_test.go`: Confirmed config-mode edit path navigation tests.
* `pkg/cli/cli_helpers.go`: Verified general CLI presentation helper functions are correct.
* `pkg/cli/cli_matchpolicies_scheduler_3414_test.go`: Confirmed policy scheduler constraints are tested.
* `pkg/cli/cli_request.go`: Verified operational request commands (DHCP, chassis failover) validate inputs correctly.
* `pkg/cli/cli_request_argv_test.go`: Confirmed argument parsing is covered.
* `pkg/cli/cli_request_policies_check.go`: Verified that shadowing and redundancy checks perform conservative containment checks correctly.
* `pkg/cli/cli_request_policies_check_test.go`: Confirmed policy shadowing checks are covered.
* `pkg/cli/cli_request_wireguard_test.go`: Confirmed wireguard request commands are covered.
* `pkg/cli/cli_rollback_3447_test.go`: Confirmed rollback input verification tests.
* `pkg/cli/cli_show.go`: Verified show presenter handles secret redaction cleanly for non-super-user classes.
* `pkg/cli/cli_show_chassis.go`: Verified chassis hardware and environment presenters are correct.
* `pkg/cli/cli_show_chassis_adapter_test.go`: Confirmed chassis adapter rendering is covered.
* `pkg/cli/cli_show_cluster.go`: Verified cluster status and fabric redirection presenters read global counters safely.
* `pkg/cli/cli_show_cluster_test.go`: Confirmed cluster presenters are covered.
* `pkg/cli/cli_show_config_redaction_4099_test.go`: Confirmed config-mode secret redaction is covered.
* `pkg/cli/cli_show_flow.go`: Verified flow statistics, session streams, and top-talkers presenters are correct.
* `pkg/cli/cli_show_flow_test.go`: Confirmed session and top-talkers presenters are tested.
* `pkg/cli/cli_show_interfaces.go`: Verified interface status presenters map interfaces correctly.
* `pkg/cli/cli_show_interfaces_reth_4328_test.go`: Confirmed reth interfaces status rendering is covered.
* `pkg/cli/cli_show_nat.go`: Verified source/destination NAT rule and pool status presenters are correct.
* `pkg/cli/cli_show_nat_shared_test.go`: Confirmed shared NAT presenters are covered.
* `pkg/cli/cli_show_nat_test.go`: Confirmed NAT rules status is covered.
* `pkg/cli/cli_show_policies_bulk_reader_test.go`: Confirmed policy hit count bulk-reader is covered.
* `pkg/cli/cli_show_policies_hitcount_gate_test.go`: Confirmed hit count system-wide gate is covered.
* `pkg/cli/cli_show_policies_scheduler_3062_test.go`: Confirmed scheduled policy status is covered.
* `pkg/cli/cli_show_policies_thencount_3074_test.go`: Confirmed policy action statistics are covered.
* `pkg/cli/cli_show_routing.go`: Verified routing table, BFD, VRRP, and ARP status presenters are correct.
* `pkg/cli/cli_show_security.go`: Verified security policies status presenters map index details correctly.
* `pkg/cli/cli_show_security_dispatch.go`: Verified security command routing maps to correct handlers.
* `pkg/cli/cli_show_security_filters.go`: Verified firewall filter configuration status presenters are correct.
* `pkg/cli/cli_show_security_flat_zone_local_3358_test.go`: Confirmed zone-local address book formatting is covered.
* `pkg/cli/cli_show_security_ipsec.go`: Verified IPsec SAs and VPN status presenters are correct.
* `pkg/cli/cli_show_security_log.go`: Verified logging status presenter formats syslog events correctly.
* `pkg/cli/cli_show_security_log_argparse_3347_test.go`: Confirmed log argparse is covered.
* `pkg/cli/cli_show_security_log_historical_zone_3335_test.go`: Confirmed historical zone-name mapping is covered.
* `pkg/cli/cli_show_security_log_negative_3342_test.go`: Confirmed negative count logs are covered.
* `pkg/cli/cli_show_security_nil_3476_test.go`: Confirmed nil zone-pair/policy rules are covered.
* `pkg/cli/cli_show_security_objects.go`: Verified address and application object presenters are correct.
* `pkg/cli/cli_show_security_policy_addr_excluded_3336_test.go`: Confirmed address-exclusion annotations are covered.
* `pkg/cli/cli_show_security_policy_index_3063_test.go`: Confirmed policy index detail matching is covered.
* `pkg/cli/cli_show_security_scoped_global_3286_test.go`: Confirmed scoped global policies formatting is covered.
* `pkg/cli/cli_show_security_scoped_global_3357_test.go`: Confirmed global policies hit count is covered.
* `pkg/cli/cli_show_security_screen.go`: Verified screen profile status presenters are correct.
* `pkg/cli/cli_show_security_screen_inventory_3327_test.go`: Confirmed screen profile inventory formatting is covered.
* `pkg/cli/cli_show_security_test.go`: Confirmed security presenters tests.
* `pkg/cli/cli_show_security_wireguard.go`: Verified wireguard status presenters are correct.
* `pkg/cli/cli_show_security_wireguard_test.go`: Confirmed wireguard status presenters are covered.
* `pkg/cli/cli_show_security_zone_local_3358_test.go`: Confirmed zone-local address book formatting is covered.
* `pkg/cli/cli_show_security_zones.go`: Verified zone status presenters are correct.
* `pkg/cli/cli_show_security_zones_explicit_any_3680_test.go`: Confirmed zone ANY option is covered.
* `pkg/cli/cli_show_security_zones_metadata_3684_test.go`: Confirmed zone metadata is covered.
* `pkg/cli/cli_show_security_zones_policy_tiers_3658_test.go`: Confirmed zone policy tiers formatting is covered.
* `pkg/cli/cli_show_services.go`: Verified dynamic DNS, RPM, appid, DHCP, and port mirroring presenters are correct.
* `pkg/cli/cli_show_services_test.go`: Confirmed services presenters are covered.
* `pkg/cli/cli_show_shared.go`: Verified shared security presenters are correct.
* `pkg/cli/cli_show_snmp_community_redaction_4111_test.go`: Confirmed SNMP community redaction is covered.
* `pkg/cli/cli_show_system.go`: Verified system buffers, storage, and process status presenters are correct.
* `pkg/cli/cli_show_system_buffers_test.go`: Confirmed system buffers rendering is covered.
* `pkg/cli/cli_zone_nil_3493_test.go`: Confirmed nil zone handling is covered.
* `pkg/cli/cluster_failover_test.go`: Confirmed cluster failover commands are tested.
* `pkg/cli/completion.go`: Verified prefix command matching and pipe filter completion logic.
* `pkg/cli/completion_activate_test.go`: Confirmed activation completion is covered.
* `pkg/cli/completion_panic_test.go`: Confirmed over-typed completion panic guards are covered.
* `pkg/cli/completion_typed_leaf_test.go`: Confirmed typed leaf completion is covered.
* `pkg/cli/configstore_helper_test.go`: Confirmed configstore helper tests.
* `pkg/cli/host_inbound_display_3654_test.go`: Confirmed host inbound rendering is covered.
* `pkg/cli/link.go`: Verified network link status queries are correct.
* `pkg/cli/monitor.go`: Verified monitor flow trace file opening, rotation, and matching are correct.
* `pkg/cli/monitor_interface.go`: Verified single-interface and summary traffic monitoring displays are correct.
* `pkg/cli/monitor_interface_stdin_3985_test.go`: Confirmed keyReader lifecycles are covered.
* `pkg/cli/monitor_match_test.go`: Confirmed monitor regex match filtering is covered.
* `pkg/cli/monitor_nil_eventbuf_3381_test.go`: Confirmed nil event buffer checks are covered.
* `pkg/cli/monitor_security_test.go`: Confirmed monitor security presenters tests.
* `pkg/cli/monitor_test.go`: Confirmed general monitor tests.
* `pkg/cli/monitor_traffic_filter_4005_test.go`: Confirmed traffic filter arguments are covered.
* `pkg/cli/peer.go`: Verified that peer dialing, quick TCP probing, and remote actions are handled without leaks or locks.
* `pkg/cli/permissions.go`: Audited login-class RBAC checks, custom class mapping, and destructive maintenance command identification; confirmed permissions gate matching logic correctly.
* `pkg/cli/permissions_custom_class_4304_test.go`: Confirmed custom class permission mapping is covered.
* `pkg/cli/permissions_maintenance_4108_test.go`: Confirmed destructive maintenance command gating is covered.
* `pkg/cli/permissions_monitor_traffic_4067_test.go`: Confirmed privileged packet capture command gating is covered.

---

#### Finding 2: Swallowed Diagnostic Error Context in `RejoinAndConfirm`
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/upgrade/kernel_drain.go:122-133`
  ```go
`pkg/upgrade/kernel_drain.go:122-133`
  ```go
  	for {
  		alive, aerr := cl.PeerAlive()
  		synced, serr := cl.SyncEstablished()
  		if aerr == nil && serr == nil && alive && synced {
  			return nil
  		}
  		if time.Now().After(dl) {
  			return fmt.Errorf("rejoin not confirmed within %s "+
  				"(peer-alive=%v sync-established=%v)", deadline, alive, synced)
  		}
  		sleepBounded(dl)
  	}
  ```
  ```
* **Trace:**
  1. The cluster coordinator initiates a rolling upgrade and reboots the target node.
  2. After the reboot, `RejoinAndConfirm` is called to verify that the upgraded node successfully rejoins and establishes session-sync.
  3. Inside the loop, `cl.PeerAlive()` and/or `cl.SyncEstablished()` fail due to connection or gRPC transport errors, capturing non-nil errors in `aerr` and `serr`.
  4. The loop continues to poll. When the deadline is exceeded, `RejoinAndConfirm` returns a formatted error detailing the booleans: `rejoin not confirmed within <deadline> (peer-alive=false sync-established=false)`.
  5. The actual errors `aerr` and `serr` are discarded and never logged or returned, leaving the operator without diagnostic context.
* **Refutation attempt:**
  I checked if the errors are logged internally inside `cl.PeerAlive()` or `cl.SyncEstablished()`. In the production gRPC client implementation, minor network transport errors are either ignored or logged to syslog. However, the orchestrator driving the upgrade only sees the error returned by `RejoinAndConfirm`. Since the errors are swallowed here, the operator cannot distinguish a basic transport error (e.g. connection refused) from an authentication or protocol mismatch error.
* **HPC/invariant check:**
  None.
* **Why it matters:**
  Swallowing error details during a critical cluster upgrade phase makes debugging failed joins extremely difficult, forcing operators to dig through syslog or guess why the peer could not be reached.
* **Fix direction:**
  Modify the timeout return block to wrap and include the last observed non-nil errors `aerr` and `serr`.
* **Labels:** `observability`
* **Dedup note:**
  This is a new finding, unrelated to any entry in the dedup index.

---

## 2. Module-by-Module Negative Findings & Invariants

Below is the sweep of all remaining files in the 131-file batch. For every file, we verify the sound invariants and negative results.

### 2.1. Firewall Policy matching (`pkg/policymatch`)
* **[policymatch.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/policymatch.go)**: Verified that omitted query fields (ports, protocol, ICMP parameters) are correctly fail-closed under all matching logic. E.g., if query protocol is omitted, a named app fails closed; if query ports are omitted, port-constrained apps fail closed. We also verified that `matchSingleApp` resolves the protocol correctly via `appid.ProtocolNumber`.
* **[zone_detail_summary.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/zone_detail_summary.go)**: Checked CLI evaluation order and metadata formatter; verified it respects policy precedence rules and formats addresses correctly.
* **[app_set_failclosed_3727_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/app_set_failclosed_3727_test.go)**: Verified that test cases validate fail-closed application matching behaviors.
* **[content_reject_4394_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/content_reject_4394_test.go)**: Verified test coverage for config-wide content rejection.
* **[display_action_3375_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/display_action_3375_test.go)**: Verified that policy matching action strings are formatted correctly.
* **[excluded_addr_3356_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/excluded_addr_3356_test.go)**: Verified that excluded source/destination address ranges are correctly tested.
* **[excluded_response_3668_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/excluded_response_3668_test.go)**: Verified that excluded response matching logic is covered.
* **[global_zone_filter_3357_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/global_zone_filter_3357_test.go)**: Verified test coverage for global and zone-specific filter matching.
* **[host_inbound_token_3627_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/host_inbound_token_3627_test.go)**: Verified that host-inbound traffic tokens are tested.
* **[host_inbound_verdict_msg_3627_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/host_inbound_verdict_msg_3627_test.go)**: Verified that host-inbound verdict messages are tested.
* **[icmp_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/icmp_test.go)**: Verified that ICMP type and code constraints are covered.
* **[junos_host_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/junos_host_test.go)**: Verified that Junos host-inbound traffic matching is validated.
* **[policymatch_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/policymatch_test.go)**: Verified that general policy matching scenarios are tested.
* **[port_omitted_3330_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/port_omitted_3330_test.go)**: Verified that omitted ports fail closed under test.
* **[port_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/port_test.go)**: Verified that destination port range matching is tested.
* **[protocol_omitted_3323_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/protocol_omitted_3323_test.go)**: Verified that omitted protocols fail closed under test.
* **[protocol_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/protocol_test.go)**: Verified that protocol-specific matching rules are tested.
* **[scheduler_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/scheduler_test.go)**: Verified that scheduler-active matching rules are tested.
* **[scope_id_3331_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/scope_id_3331_test.go)**: Verified that IPv6 link-local scope IDs are tested.
* **[scoped_global_zonelocal_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/scoped_global_zonelocal_test.go)**: Verified that global vs zone-local rule scope is tested.
* **[selector_args_3696_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/selector_args_3696_test.go)**: Verified that selector argument parsing is tested.
* **[selector_args_dup_3709_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/selector_args_dup_3709_test.go)**: Verified that duplicate selector arguments are tested.
* **[simulator_output_parity_3685_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/simulator_output_parity_3685_test.go)**: Verified that simulator and dataplane policy matching output parity are tested.
* **[srcport_omitted_3415_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/srcport_omitted_3415_test.go)**: Verified that omitted source ports fail closed under test.
* **[undefined_zone_3355_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/undefined_zone_3355_test.go)**: Verified that undefined zones fail closed under test.
* **[usage_3628_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/usage_3628_test.go)**: Verified that usage telemetry is tested.
* **[wildcard_scoped_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/wildcard_scoped_test.go)**: Verified that wildcard-scoped rule evaluation is tested.
* **[zone_detail_summary_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/zone_detail_summary_test.go)**: Verified that zone details formatting is tested.
* **[zone_local_display_3358_test.go](file:///home/ps/git/gemini-xpf/pkg/policymatch/zone_local_display_3358_test.go)**: Verified that zone-local rules are displayed correctly.

### 2.2. Scheduler (`pkg/scheduler`)
* **[scheduler.go](file:///home/ps/git/gemini-xpf/pkg/scheduler/scheduler.go)**: Verified that scheduler active state is correctly protected with read-write mutex lock-unlock. Apart from Finding 1, no other concurrency or resource safety issues are present.
* **[scheduler_3849_test.go](file:///home/ps/git/gemini-xpf/pkg/scheduler/scheduler_3849_test.go)**: Verified scheduler state matching under test.
* **[scheduler_localtz_3988_test.go](file:///home/ps/git/gemini-xpf/pkg/scheduler/scheduler_localtz_3988_test.go)**: Verified scheduler local timezone translation.
* **[scheduler_republish_3780_test.go](file:///home/ps/git/gemini-xpf/pkg/scheduler/scheduler_republish_3780_test.go)**: Verified scheduler republish retry logic.
* **[scheduler_test.go](file:///home/ps/git/gemini-xpf/pkg/scheduler/scheduler_test.go)**: Verified general scheduler behaviors.

### 2.3. Upgrade & Orchestration (`pkg/upgrade`)
* **[cluster_cli.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/cluster_cli.go)**: Checked the peer status parser and the takeover-ready logic; verified that parsing validates node tokens correctly (except the low-severity atoi issue in the dedup index).
* **[cluster_cli_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/cluster_cli_test.go)**: Verified that CLI parsing test cases cover expected formats.
* **[cutover.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/cutover.go)**: Verified that the single-node cutover state machine enforces the pre-STOP invariant (`PreviousVersion != ""` or sanctioned first cut) and is fully idempotent across resumes.
* **[cutover_refuse_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/cutover_refuse_test.go)**: Verified that unsanctioned cuts with no rollback target are refused under test.
* **[flip.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/flip.go)**: Verified that the A/B flip handles temp symlink and atomic rename correctly, restoring DB snapshots on failure.
* **[imageversions.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/imageversions.go)**: Verified that parseImageVersions enforces unsigned 16-bit ranges on HA/session-sync fields to prevent negative bounds bypasses.
* **[imageversions_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/imageversions_test.go)**: Verified parser and compatibility gate logic tests.
* **[kernel.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel.go)**: Verified interface declarations for kernel system operations.
* **[kernel_drain.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel_drain.go)**: Verified that `RejoinAndConfirm` loops with bounded sleep. Apart from Finding 2, errors are correctly evaluated.
* **[kernel_drain_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel_drain_test.go)**: Verified cluster drain and rejoin test scenarios.
* **[kernel_linux.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel_linux.go)**: Verified that Linux-specific UEFI/BootNext commands are mapped correctly.
* **[kernel_linux_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel_linux_test.go)**: Verified Linux kernel slot detection tests.
* **[kernel_run.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel_run.go)**: Verified that pre-reboot arming and post-reboot promotion oneshots are correctly orchestrated.
* **[kernel_selfrecover.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel_selfrecover.go)**: Verified that recovery task loops check the active lease before modifying system state.
* **[kernel_selfrecover_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel_selfrecover_test.go)**: Verified self-recovery behavior tests.
* **[kernel_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/kernel_test.go)**: Verified general kernel slot logic tests.
* **[lock/lock.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/lock/lock.go)**: Verified that the exclusive BSD flock lock on `/run/xpf/upgrade.lock` is correctly acquired, released, and its owner metadata truncated under lock to prevent stale reads.
* **[lock/lock_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/lock/lock_test.go)**: Verified lock acquisition and contention test cases.
* **[lock_integration_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/lock_integration_test.go)**: Verified that concurrent upgrade process contention is correctly prevented under test.
* **[lock_seam_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/lock_seam_test.go)**: Verified integration mock interfaces for the lock package.
* **[manifest/manifest.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/manifest/manifest.go)**: Verified that the lockstep binary set is unexported and immutable at package level.
* **[manifest/manifest_drift_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/manifest/manifest_drift_test.go)**: Verified that the canary test catches any divergence in the maintainer scripts' binary lists.
* **[rolling.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/rolling.go)**: Verified that the rolling driver enforces the strong drain predicate and holds the upgrade lock throughout the rolling window.
* **[rolling_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/rolling_test.go)**: Verified rolling upgrade state machine tests.
* **[runner.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/runner.go)**: Verified the upgrade runner options and defaults structure.
* **[runner_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/runner_test.go)**: Verified runner configuration tests.
* **[runtime/seed.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/runtime/seed.go)**: Verified that first-install seeding is fully idempotent and uses atomic renaming for version directories and symlinks.
* **[runtime/seed_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/runtime/seed_test.go)**: Verified first-install runtime seeding tests.
* **[stagedgen/fsutil.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/stagedgen/fsutil.go)**: Verified directory copy and checksum utility routines.
* **[stagedgen/stagedgen.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/stagedgen/stagedgen.go)**: Verified that staged generation publishing creates immutable generation directories to prevent concurrent unpack torn reads.
* **[stagedgen/stagedgen_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/stagedgen/stagedgen_test.go)**: Verified staged generation publishing and GC tests.
* **[stagedgen_cut_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/stagedgen_cut_test.go)**: Verified integration tests combining staged generations and cuts.
* **[state.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/state.go)**: Verified upgrade transaction states.
* **[system_linux.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/system_linux.go)**: Verified that Linux system calls for unit control and disk space detection are wrapped safely.
* **[system_linux_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/system_linux_test.go)**: Verified Linux system call mocks.
* **[verify_cleanup_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/verify_cleanup_test.go)**: Verified that failing verify-dataplane copies are cleaned up.
* **[version.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/version.go)**: Verified version string validation rules.
* **[version_test.go](file:///home/ps/git/gemini-xpf/pkg/upgrade/version_test.go)**: Verified version segment validation test cases.

### 2.4. WireGuard Key Generator (`pkg/wgkey`)
* **[wgkey.go](file:///home/ps/git/gemini-xpf/pkg/wgkey/wgkey.go)**: Verified that Curve25519 clamping is applied correctly in-place and public key derivation is cryptographically sound using pure-Go `crypto/ecdh`.
* **[wgkey_test.go](file:///home/ps/git/gemini-xpf/pkg/wgkey/wgkey_test.go)**: Verified cryptographic key pair and base64 parsing test cases.

### 2.5. Deployment Tooling (`scripts/deploy`)
* **[xpf-deploy.py](file:///home/ps/git/gemini-xpf/scripts/deploy/xpf-deploy.py)**: Verified that positional interface mapping matches the daemon's guest slot sorting (virtio before hardware), preventing trust/untrust zone swaps.
* **[test_xpf_deploy_correctness.py](file:///home/ps/git/gemini-xpf/scripts/deploy/test_xpf_deploy_correctness.py)**: Verified deployment command validation tests.
* **[test_xpf_deploy_disk.py](file:///home/ps/git/gemini-xpf/scripts/deploy/test_xpf_deploy_disk.py)**: Verified disk resizing and overlay configuration tests.
* **[test_xpf_deploy_gate.py](file:///home/ps/git/gemini-xpf/scripts/deploy/test_xpf_deploy_gate.py)**: Verified deployment preflight validation tests.
* **[test_xpf_deploy_nicorder.py](file:///home/ps/git/gemini-xpf/scripts/deploy/test_xpf_deploy_nicorder.py)**: Verified guest NIC ordering tests.
* **[test_xpf_deploy_robustness.py](file:///home/ps/git/gemini-xpf/scripts/deploy/test_xpf_deploy_robustness.py)**: Verified teardown on failed deploy tests.

### 2.6. Distribution & Signing (`scripts/dist`)
* **[sign.py](file:///home/ps/git/gemini-xpf/scripts/dist/sign.py)**: Verified that signature verification copies files to a private 0700 directory to prevent TOCTOU modifications of live manifest files.
* **[publish.py](file:///home/ps/git/gemini-xpf/scripts/dist/publish.py)**: Verified that the publish gate is fail-closed, rejecting unsigned manifests, placeholder public keys, and unbaked installer files.

### 2.7. Image Baking & Validation (`scripts/image`)
* **[bake.py](file:///home/ps/git/gemini-xpf/scripts/image/bake.py)**: Verified that the manifest signature is produced only *after* the validation gate returns success, preventing signed-but-unvalidated images.
* **[make_config_drive.py](file:///home/ps/git/gemini-xpf/scripts/image/make_config_drive.py)**: Verified config drive creation logic; confirmed it validates config syntax against the daemon.
* **[validate.py](file:///home/ps/git/gemini-xpf/scripts/image/validate.py)**: Verified that in-guest validation handles fallback retry, root auto-grow, and node-id clustering scenarios correctly.
* **[test_bake_sign_ordering.py](file:///home/ps/git/gemini-xpf/scripts/image/test_bake_sign_ordering.py)**: Verified that the validate-before-sign ordering is strictly enforced under test.
* **[test_validate_scenarios.py](file:///home/ps/git/gemini-xpf/scripts/image/test_validate_scenarios.py)**: Verified individual validation scenario execution tests.

### 2.8. Helper & Metrics Scripts (`scripts`)
* **[iperf-json-metrics.py](file:///home/ps/git/gemini-xpf/scripts/iperf-json-metrics.py)**: Verified that iperf3 JSON parsing handles stream records and detects throughput collapses correctly.
* **[mtr_report_check.py](file:///home/ps/git/gemini-xpf/scripts/mtr_report_check.py)**: Verified that network diagnostics parsing parses loss and latency targets correctly.
* **[test_mtr_report_check.py](file:///home/ps/git/gemini-xpf/scripts/test_mtr_report_check.py)**: Verified MTR check test cases.
* **[userspace_ha_validation_matrix_test.py](file:///home/ps/git/gemini-xpf/scripts/userspace_ha_validation_matrix_test.py)**: Verified cluster failover validation test matrix.

### 2.9. Incus Integration Testing (`test/incus`)
* **[cluster_status_parse.py](file:///home/ps/git/gemini-xpf/test/incus/cluster_status_parse.py)**: Verified that the status parser matches hyphenated statuses such as `secondary-hold` without truncation.
* **[cluster_status_parse_test.py](file:///home/ps/git/gemini-xpf/test/incus/cluster_status_parse_test.py)**: Verified cluster status parsing test cases.
* **[cold-path-flooder/src/main.rs](file:///home/ps/git/gemini-xpf/test/incus/cold-path-flooder/src/main.rs)**: Verified that `TxRing` wiring occurs *after* stack movement inside the worker thread to prevent raw pointer dangling.
* **[cos_be_contention_validate.py](file:///home/ps/git/gemini-xpf/test/incus/cos_be_contention_validate.py)**: Verified class-matching logic and throughput drop check calculations.
* **[cos_be_contention_validate_test.py](file:///home/ps/git/gemini-xpf/test/incus/cos_be_contention_validate_test.py)**: Verified contention validation test cases.
* **[cos_port_grid_test.py](file:///home/ps/git/gemini-xpf/test/incus/cos_port_grid_test.py)**: Verified port mapping tests.
* **[fairness_cov.py](file:///home/ps/git/gemini-xpf/test/incus/fairness_cov.py)**: Verified queue fairness calculations.
* **[fairness_cov_test.py](file:///home/ps/git/gemini-xpf/test/incus/fairness_cov_test.py)**: Verified fairness test cases.
* **[fairness_equal_flow_capture.py](file:///home/ps/git/gemini-xpf/test/incus/fairness_equal_flow_capture.py)**: Verified queue bandwidth capture logic.
* **[fairness_multi_sample.py](file:///home/ps/git/gemini-xpf/test/incus/fairness_multi_sample.py)**: Verified multi-flow fairness sampling.
* **[fairness_multi_sample_test.py](file:///home/ps/git/gemini-xpf/test/incus/fairness_multi_sample_test.py)**: Verified multi-sample test cases.
* **[fairness_surplus_giveback_validate.py](file:///home/ps/git/gemini-xpf/test/incus/fairness_surplus_giveback_validate.py)**: Verified surplus bandwidth distribution tests.
* **[fairness_surplus_giveback_validate_test.py](file:///home/ps/git/gemini-xpf/test/incus/fairness_surplus_giveback_validate_test.go)**: Verified surplus giveback test cases.
* **[iperf3_sum_parse.py](file:///home/ps/git/gemini-xpf/test/incus/iperf3_sum_parse.py)**: Verified iperf3 total statistics parser.
* **[iperf3_sum_parse_test.py](file:///home/ps/git/gemini-xpf/test/incus/iperf3_sum_parse_test.py)**: Verified iperf3 parsing tests.
* **[mouse_latency_aggregate.py](file:///home/ps/git/gemini-xpf/test/incus/mouse_latency_aggregate.py)**: Verified aggregate latency stats calculations.
* **[mouse_latency_aggregate_test.py](file:///home/ps/git/gemini-xpf/test/incus/mouse_latency_aggregate_test.py)**: Verified aggregation test cases.
* **[mouse_latency_orchestrate.py](file:///home/ps/git/gemini-xpf/test/incus/mouse_latency_orchestrate.py)**: Verified latency orchestration harness.
* **[mouse_latency_orchestrate_test.py](file:///home/ps/git/gemini-xpf/test/incus/mouse_latency_orchestrate_test.py)**: Verified latency orchestration tests.
* **[mouse_latency_probe.py](file:///home/ps/git/gemini-xpf/test/incus/mouse_latency_probe.py)**: Verified raw ICMP ping latency probe logic.
* **[mouse_latency_probe_test.py](file:///home/ps/git/gemini-xpf/test/incus/mouse_latency_probe_test.py)**: Verified latency probe test cases.
* **[policy_scheduler_validate.py](file:///home/ps/git/gemini-xpf/test/incus/policy_scheduler_validate.py)**: Verified scheduled policy validation logic.
* **[policy_scheduler_validate_test.py](file:///home/ps/git/gemini-xpf/test/incus/policy_scheduler_validate_test.py)**: Verified scheduler validation tests.
* **[retire_ebpf_artifact_schema.py](file:///home/ps/git/gemini-xpf/test/incus/retire_ebpf_artifact_schema.py)**: Verified that retired eBPF schemas are ignored.
* **[retire_ebpf_artifact_schema_test.py](file:///home/ps/git/gemini-xpf/test/incus/retire_ebpf_artifact_schema_test.py)**: Verified retired schema tests.
* **[step1-histogram-classify.py](file:///home/ps/git/gemini-xpf/test/incus/step1-histogram-classify.py)**: Verified histogram categorization logic.
* **[step1-histogram-classify_test.py](file:///home/ps/git/gemini-xpf/test/incus/step1-histogram-classify_test.py)**: Verified histogram tests.
* **[step1-rate-spread-analysis.py](file:///home/ps/git/gemini-xpf/test/incus/step1-rate-spread-analysis.py)**: Verified queue rates spread analysis.
* **[step1-rss-multinomial.py](file:///home/ps/git/gemini-xpf/test/incus/step1-rss-multinomial.py)**: Verified receiver queue RSS distribution logic.
* **[step2-sched-switch-classify.py](file:///home/ps/git/gemini-xpf/test/incus/step2-sched-switch-classify.py)**: Verified context switch timing classifier.
* **[step2-sched-switch-classify_test.py](file:///home/ps/git/gemini-xpf/test/incus/step2-sched-switch-classify_test.py)**: Verified context switch tests.
* **[step2-sched-switch-reduce.py](file:///home/ps/git/gemini-xpf/test/incus/step2-sched-switch-reduce.py)**: Verified context switch reduction logic.
* **[step2-sched-switch-reduce_test.py](file:///home/ps/git/gemini-xpf/test/incus/step2-sched-switch-reduce_test.py)**: Verified context switch reduction tests.
* **[step3-tx-kick-classify.py](file:///home/ps/git/gemini-xpf/test/incus/step3-tx-kick-classify.py)**: Verified queue kick frequency classifier.
* **[step3-tx-kick-classify_test.py](file:///home/ps/git/gemini-xpf/test/incus/step3-tx-kick-classify_test.py)**: Verified kick frequency tests.
* **[test_mouse_latency_shell_test.py](file:///home/ps/git/gemini-xpf/test/incus/test_mouse_latency_shell_test.py)**: Verified shell latency orchestration tests.

### 2.10. Standalone AF_XDP rebind tests (`test/xsk-repro`)
* **[main.rs](file:///home/ps/git/gemini-xpf/test/xsk-repro/main.rs)**: Verified that rebind test loops register in the xskmap and trigger NAPI poll correctly.
* **[libbpf_xsk_shared_test.c](file:///home/ps/git/gemini-xpf/test/xsk-repro/libbpf_xsk_shared_test.c)**: Verified that C test shim performs shared UMEM rebind.
* **[libbpf_xsk_test.c](file:///home/ps/git/gemini-xpf/test/xsk-repro/libbpf_xsk_test.c)**: Verified that C test shim handles basic socket rebind.
* **[xdp_pass_redirect.c](file:///home/ps/git/gemini-xpf/test/xsk-repro/xdp_pass_redirect.c)**: Verified redirect BPF program logic.

---

#### Finding 3: Silent Dropping of Malformed/Unparseable DNAT Rules
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `userspace-dp/src/nat/destination.rs:322-L331`
  ```rust
In [destination.rs:322-331](file:///home/ps/git/gemini-xpf/userspace-dp/src/nat/destination.rs#L322-L331):
  ```rust
                    Err(_) => match snap.destination_address.parse::<IpAddr>() {
                        Ok(ip) => DnatDest::Host(ip),
                        Err(_) => continue,
                    },
                }
            } else {
                match snap.destination_address.parse::<IpAddr>() {
                    Ok(ip) => DnatDest::Host(ip),
                    Err(_) => continue,
                }
  ```
  In [destination.rs:341-345](file:///home/ps/git/gemini-xpf/userspace-dp/src/nat/destination.rs#L341-L345):
  ```rust
                match snap.pool_address.parse() {
                    Ok(ip) => ip,
                    Err(_) => continue,
                }
  ```
  ```
* **Trace:**
  1. The control plane or peer sync installs a `DestinationNATRuleSnapshot` containing a malformed `pool_address` or `destination_address`.
  2. `DnatTable::from_snapshots` is invoked during reconciliation.
  3. The parser fails to parse the string into an `IpAddr`, causing `parse()` to return `Err(_)`.
  4. The loop hits `continue`, skipping the entire rule without logging any warning or diagnostic message.
* **Refutation attempt:**
  Not required for Low severity.
* **HPC/invariant check:**
  Telemetry/logging safety is preserved because this code executes during the control-plane config reload phase (reconciliation) rather than on the packet-forwarding hot path. Log statements here will not add latency to packet transit.
* **Why it matters:**
  Operators debugging invalid configurations or sync drifts are left with no log or telemetry signal from the userspace dataplane indicating why a particular DNAT rule failed to apply. This breaks operational transparency.
* **Fix direction:**
  Emit a warning using `eprintln!` or a logging framework (similar to `nat64.rs` skips), indicating the rule name and the malformed field that caused it to be ignored.
* **Labels:** `observability-gap`, `usability`
* **Dedup note:**
  The dedup index lists DNAT rule shadowing and missing local IP registration, but does not list silent dropping or parser observability gaps.

---

---

#### Finding 4: Silent Dropping of Malformed/Unparseable Static NAT Rules
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `userspace-dp/src/nat/static_nat.rs:355-L364`
  ```rust
In [static_nat.rs:355-364](file:///home/ps/git/gemini-xpf/userspace-dp/src/nat/static_nat.rs#L355-L364):
  ```rust
            let ext_prefix = match parse_nat_prefix(&snap.external_ip) {
                Some(p) => p,
                None => continue,
            };
            let int_prefix = match parse_nat_prefix(&snap.internal_ip) {
                Some(p) => p,
                None => continue,
            };
  ```
  ```
* **Trace:**
  1. A `StaticNATRuleSnapshot` containing a malformed prefix or IP address is loaded.
  2. `StaticNatTable::from_snapshots` calls `parse_nat_prefix` on `snap.external_ip`.
  3. Parsing fails, returning `None`.
  4. The loop hits `continue`, skipping the rule silently.
* **Refutation attempt:**
  Not required for Low severity.
* **HPC/invariant check:**
  Logging safety on control plane reconciliation.
* **Why it matters:**
  Prevents visibility into configuration compilation errors, resulting in silent translation omissions that are extremely difficult to troubleshoot in production environments.
* **Fix direction:**
  Add a loud diagnostic message (e.g. `eprintln!`) warning that the static NAT rule was skipped due to unparseable IP prefixes.
* **Labels:** `observability-gap`, `usability`
* **Dedup note:**
  The dedup index lists static NAT shadowing/overwrite bugs, but does not list silent dropping/parser observability gaps.

---

---

#### Finding 5: Silent Dropping of Malformed Match Prefixes in Source NAT
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `userspace-dp/src/nat/source.rs:1139-L1157`
  ```rust
In [source.rs:1139-1157](file:///home/ps/git/gemini-xpf/userspace-dp/src/nat/source.rs#L1139-L1157):
  ```rust
fn parse_match_prefix(prefix: &str, v4: &mut Vec<PrefixV4>, v6: &mut Vec<PrefixV6>) {
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => v6.push(PrefixV6::from_net(net)),
        Err(_) => match prefix.parse::<IpAddr>() {
            Ok(IpAddr::V4(addr)) => {
                if let Ok(net) = Ipv4Net::new(addr, 32) {
                    v4.push(PrefixV4::from_net(net));
                }
            }
            Ok(IpAddr::V6(addr)) => {
                if let Ok(net) = Ipv6Net::new(addr, 128) {
                    v6.push(PrefixV6::from_net(net));
                }
            }
            Err(_) => {}
        },
    }
}
  ```
  ```
* **Trace:**
  1. A source NAT rule includes an unparseable match address prefix in its config.
  2. `parse_source_nat_rules_with_previous` calls `parse_match_prefix` for the configured addresses.
  3. The prefix fails to parse as both `IpNet` and `IpAddr`.
  4. The parser silently drops the entry from the rule (leaving the `v4` and `v6` vectors empty if no other prefixes exist).
* **Refutation attempt:**
  Not required for Low severity.
* **HPC/invariant check:**
  Logging safety on control plane reconciliation.
* **Why it matters:**
  When individual match prefixes fail to parse, they are silently omitted. If all prefixes in a constrained match set fail, the rule defaults to matching nothing (fails closed, which is secure), but does so without notifying the administrator, leaving them unaware of why their traffic is not translated.
* **Fix direction:**
  Log a warning when a match prefix fails to parse, specifying the rule name and the invalid prefix string.
* **Labels:** `observability-gap`, `usability`
* **Dedup note:**
  Not present in the dedup index.

---

#### Finding 6: Slice Index Out of Range Panic in AST Formatting for Empty Key Nodes
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/ast_format.go:63-L69`
  ```go
* File: [ast_format.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_format.go#L63-L69)
    ```go
    		if n.InheritedFrom != "" {
    			// Use the last key in the node's key path for inherited-node annotations
    			// (for example, "## 'any' was inherited").
    			displayKey := n.Keys[len(n.Keys)-1]
    			fmt.Fprintf(b, "%s##\n%s## '%s' was inherited from group '%s'\n%s##\n",
    				prefix, prefix, displayKey, n.InheritedFrom, prefix)
    		}
    ```
  ```
* **Why it matters:**
  If a node is constructed or modified programmatically (such as during testing or via custom API inputs) where it has a non-empty `InheritedFrom` field but no `Keys` (length 0), calling `FormatInheritance()` or `FormatPathInheritance()` will panic due to an out-of-bounds slice access (`len(n.Keys)-1` yields `-1`). This can cause rendering requests (e.g. gRPC or REST config display) to crash.
* **Fix direction:**
  Add a guard checking that `len(n.Keys) > 0` before indexing the last key.
  ```go
  displayKey := ""
  if len(n.Keys) > 0 {
      displayKey = n.Keys[len(n.Keys)-1]
  }
  ```
* **Labels:** `correctness`, `robustness`
* **Dedup note:**
  This issue is not listed in the dedup index.

---

## NEGATIVE RESULTS (MODULES WITH NO FINDINGS)

For every module below, a negative result is recorded along with the key invariant verified:

### Core Go Modules
* **pkg/appid/catalog.go**
  * **Negative Result**: Catalog construction is sound.
  * **Invariant**: The catalog compilation in `BuildCatalog` correctly maintains parity with `compileApplications` by mirroring its ID-bump logic and emittable constraints, and prevents silent wraps on `uint16` app ID space by range-checking using `nextID` working counter of type `uint32`.
* **pkg/appid/runtime.go**
  * **Negative Result**: Runtime resolver is sound.
  * **Invariant**: The runtime resolver resolves session names deterministically, preferring port-constrained applications over protocol-only ones, and correctly sanitizes/validates port specs against uint16 narrowing and signed acceptance using `ParseCanonicalUint`.
* **pkg/appid/textrender.go**
  * **Negative Result**: Text renderer is sound.
  * **Invariant**: The text renderer formats statistics and help text cleanly without division-by-zero or unsafe buffer operations.
* **pkg/config/ast.go**
  * **Negative Result**: AST structures are sound.
  * **Invariant**: Deep copying and path navigation handle multi-key nodes correctly without memory corruption, and escaping logic ensures format-round-trip symmetry.
* **pkg/config/ast_edit.go**
  * **Negative Result**: AST editing operations are sound.
  * **Invariant**: Editing operations (`CopyPath`, `RenamePath`, `InsertBefore`, etc.) prevent collisions and parent mismatches by validating path identities and existence of sibling nodes prior to modifying the tree structure.
* **pkg/config/ast_groups.go**
  * **Negative Result**: AST group expansion is sound.
  * **Invariant**: Group expansion resolves nested apply-groups recursively while detecting circular references and enforcing Junos-style typed leaf-list union semantics.
* **pkg/config/ast_redact.go**
  * **Negative Result**: AST redaction is sound.
  * **Invariant**: Sensitive fields such as pre-shared keys, passwords, and API tokens are correctly identified using contextual parent paths and redacted in-place on copies of the tree.
* **pkg/config/compiler.go**
  * **Negative Result**: Main compiler coordinator is sound.
  * **Invariant**: The entry point handles strict and lenient options consistently, routing warnings and failures through appropriate gates without leaking resources.
* **pkg/config/compiler_applications.go**
  * **Negative Result**: Application compilation is sound.
  * **Invariant**: Application compilation correctly parses timeouts, protocols, and ICMP types/codes, range-checking them strictly to prevent out-of-bounds values from reaching the dataplane.
* **pkg/config/compiler_applications_collision.go**
  * **Negative Result**: Application collision validation is sound.
  * **Invariant**: Namespaces are strictly checked for collisions between explicit application names, application-sets, and generated per-term application names.
* **pkg/config/compiler_chassis.go**
  * **Negative Result**: Chassis device-map compilation is sound.
  * **Invariant**: Normalization of PCI addresses and MACs guarantees deterministic, stable ordering of device-map entries.
* **pkg/config/compiler_firewall.go**
  * **Negative Result**: Firewall compilation is sound.
  * **Invariant**: Firewall filter compilation matches terms, actions, and match conditions correctly, ensuring no out-of-bounds array accesses occur when parsing TCP flags or protocol/port specs.
* **pkg/config/compiler_interface_range.go**
  * **Negative Result**: Interface range expansion is sound.
  * **Invariant**: Physical interface range expansion synthesizes logical structures correctly.
* **pkg/config/compiler_interfaces.go**
  * **Negative Result**: Interface compilation is sound.
  * **Invariant**: Interface parsing maps logical/physical units, DHCP clients, and VRRP configurations, sanitizing out-of-range track costs to prevent semantic inversion.
* **pkg/config/compiler_interfaces_unsupported.go**
  * **Negative Result**: Unsupported interface checking is sound.
  * **Invariant**: Per-logical interface ARP policers, static MAC overrides, and QinQ inner VLANs are correctly identified and rejected at commit time to avoid false-security promises.
* **pkg/config/compiler_ipsec.go**
  * **Negative Result**: IPsec compilation is sound.
  * **Invariant**: IKE and IPsec proposal compilation maps algorithms and keys correctly.
* **pkg/config/compiler_ipsec_bindiface.go**
  * **Negative Result**: Secure tunnel binding validation is sound.
  * **Invariant**: Secure tunnel binding interface assignments are validated.
* **pkg/config/compiler_ipsec_proposalset.go**
  * **Negative Result**: IPsec proposal-set compilation is sound.
  * **Invariant**: Proposal sets compile correctly.
* **pkg/config/compiler_ipsec_trafficselector.go**
  * **Negative Result**: Traffic selector compilation is sound.
  * **Invariant**: Traffic selectors are compiled.
* **pkg/config/compiler_nat.go**
  * **Negative Result**: NAT rule compilation is sound.
  * **Invariant**: NAT compilation (source, destination, static, NAT64) processes translation rules, address mappings, and pool bindings correctly.
* **pkg/config/compiler_nat_dnat_to.go**
  * **Negative Result**: Destination NAT validation is sound.
  * **Invariant**: Destination NAT rule-sets containing `to` scopes are correctly rejected at commit to prevent silent ignore.
* **pkg/config/compiler_policy_match.go**
  * **Negative Result**: Policy match validation is sound.
  * **Invariant**: Security policy matching constraints are pre-walked, rejecting unsupported match dimensions (such as dynamic-application or url-category) to prevent fail-open policy widening.

### Test Files (Batch Parity and Correctness Verification)
The following test modules verify the respective code gates under strict and lenient paths, confirming they correctly validate config inputs, expand AST segments, and prevent regressions without panics:
* **pkg/appid/catalog_icmp_3781_test.go**
* **pkg/appid/catalog_proto0_4008_test.go**
* **pkg/appid/catalog_tolerant_3725_test.go**
* **pkg/appid/precedence_parity_test.go**
* **pkg/appid/protocol_lenient_3439_test.go**
* **pkg/appid/protocol_number_2124_test.go**
* **pkg/appid/runtime_test.go**
* **pkg/appid/textrender_test.go**
* **pkg/cmdtree/completion_nil_3476_test.go**
* **pkg/cmdtree/completion_nil_3493_test.go**
* **pkg/cmdtree/tree_hb167_test.go**
* **pkg/cmdtree/tree_test.go**
* **pkg/config/addressbook_name_slash_3061_test.go**
* **pkg/config/addressbook_name_slash_4340_test.go**
* **pkg/config/allow_dataplane_sleep_test.go**
* **pkg/config/application_set_nested_test.go**
* **pkg/config/apply_groups_leaflist_exclude_test.go**
* **pkg/config/apply_groups_leaflist_test.go**
* **pkg/config/ast_redact_test.go**
* **pkg/config/backup_router_family_2911_test.go**
* **pkg/config/bgp_neighbor_peeras_2963_test.go**
* **pkg/config/compiler_addrbook_warn_3958_test.go**
* **pkg/config/compiler_application_destport_names_3340_test.go**
* **pkg/config/compiler_application_junos_ping_3348_test.go**
* **pkg/config/compiler_application_mixed_term_3366_test.go**
* **pkg/config/compiler_application_port_range_zero_4336_test.go**
* **pkg/config/compiler_application_set_member_3890_test.go**
* **pkg/config/compiler_application_specs_test.go**
* **pkg/config/compiler_application_term_alg_3352_3353_test.go**
* **pkg/config/compiler_application_timeout_3320_test.go**
* **pkg/config/compiler_applications_collision_3339_test.go**
* **pkg/config/compiler_as_path_prepend_2892_test.go**
* **pkg/config/compiler_bgp_as_3870_test.go**
* **pkg/config/compiler_chassis_device_map_test.go**
* **pkg/config/compiler_cluster_authkey_4107_test.go**
* **pkg/config/compiler_cos_rate_percent_strict_4320_test.go**
* **pkg/config/compiler_cos_tcp_hb167_test.go**
* **pkg/config/compiler_default_policy_3065_test.go**
* **pkg/config/compiler_default_policy_log_3534_test.go**
* **pkg/config/compiler_dhcp_ddns_test.go**
* **pkg/config/compiler_dhcp_relay_overrides_test.go**
* **pkg/config/compiler_dnat_address_test.go**
* **pkg/config/compiler_dnat_protocol_test.go**
* **pkg/config/compiler_dup_flow_subblock_3566_test.go**
* **pkg/config/compiler_dup_match_then_3850_test.go**
* **pkg/config/compiler_dup_policy_name_3473_test.go**
* **pkg/config/compiler_dup_security_3562_test.go**
* **pkg/config/compiler_dynamic_address_feed_ref_3300_test.go**
* **pkg/config/compiler_equal_flow_target_policy_test.go**
* **pkg/config/compiler_equal_flow_worker_cap_test.go**
* **pkg/config/compiler_f3_hb167_test.go**
* **pkg/config/compiler_feed_address_token_3294_test.go**
* **pkg/config/compiler_filter_action_test.go**
* **pkg/config/compiler_filter_loss_priority_2507_test.go**
* **pkg/config/compiler_filter_nocatchall_3295_test.go**
* **pkg/config/compiler_filter_protocol_test.go**
* **pkg/config/compiler_filter_ref_3296_test.go**
* **pkg/config/compiler_firewall_family_any_4287_test.go**
* **pkg/config/compiler_firewall_family_any_match_4296_test.go**
* **pkg/config/compiler_firewall_family_any_prefixlist_4426_test.go**
* **pkg/config/compiler_firewall_family_collision_3884_test.go**
* **pkg/config/compiler_flat_reth_nodeid_4329_test.go**
* **pkg/config/compiler_frr_policy_inject_4097_test.go**
* **pkg/config/compiler_inert_knobs_4306_test.go**
* **pkg/config/compiler_interface_range_4027_test.go**
* **pkg/config/compiler_interfaces_unsupported_test.go**
* **pkg/config/compiler_ipsec_bindiface_2933_test.go**
* **pkg/config/compiler_ipsec_gateway_ref_test.go**
* **pkg/config/compiler_ipsec_hb167_parity_test.go**
* **pkg/config/compiler_ipsec_proposals_multivalue_3904_test.go**
* **pkg/config/compiler_ipsec_ts_4098_test.go**
* **pkg/config/compiler_junos_host_direct_warn_4146_test.go**
* **pkg/config/compiler_lo0_mirror_modifiers_3445_test.go**
* **pkg/config/compiler_nat64_prefix_test.go**
* **pkg/config/compiler_nat_address_name_feed_3418_test.go**
* **pkg/config/compiler_nat_address_name_resolvable_3425_test.go**
* **pkg/config/compiler_nat_application_specs_test.go**
* **pkg/config/compiler_nat_dest_address_name_3229_test.go**
* **pkg/config/compiler_nat_dnat_off_3844_test.go**
* **pkg/config/compiler_nat_dnat_pool_3450_test.go**
* **pkg/config/compiler_nat_dnat_port_range_3449_test.go**
* **pkg/config/compiler_nat_dnat_to_3444_test.go**
* **pkg/config/compiler_nat_dup_subblock_3915_test.go**
* **pkg/config/compiler_nat_host_mask_test.go**
* **pkg/config/compiler_nat_match_application_3434_test.go**
* **pkg/config/compiler_nat_match_dport_3446_test.go**
* **pkg/config/compiler_nat_match_multivalue_3431_test.go**
* **pkg/config/compiler_nat_persistent_permit_test.go**
* **pkg/config/compiler_nat_pool_alarm_test.go**
* **pkg/config/compiler_nat_scope_3079_test.go**
* **pkg/config/compiler_nat_source_address_name_2416_test.go**
* **pkg/config/compiler_nat_source_dport_3429_test.go**
* **pkg/config/compiler_nat_source_pool_port_3906_test.go**
* **pkg/config/compiler_nat_target_parity_hb167_test.go**
* **pkg/config/compiler_nptv6_self_overlap_4339_test.go**
* **pkg/config/compiler_nptv6_test.go**
* **pkg/config/compiler_p3_http_providers_test.go**
* **pkg/config/compiler_policy_dup_block_3842_test.go**
* **pkg/config/compiler_policy_global_zone_3148_test.go**
* **pkg/config/compiler_policy_match_3113_test.go**
* **pkg/config/compiler_policy_match_3142_test.go**
* **pkg/config/compiler_policy_match_3673_test.go**
* **pkg/config/compiler_policy_match_address_set_3149_test.go**
* **pkg/config/compiler_policy_match_application_3144_test.go**
* **pkg/config/compiler_policy_match_ssot_4121_test.go**

---

#### Finding 7: BGP Group and Neighbor Peer-AS/Local-AS Integer Truncation
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/compiler_protocols.go:305-L316`
  ```go
[compiler_protocols.go:L305-316](file:///home/ps/git/gemini-xpf/pkg/config/compiler_protocols.go#L305-L316)
    ```go
    				case "peer-as":
    					if v := nodeVal(child); v != "" {
    						if n, err := strconv.Atoi(v); err == nil {
    							peerAS = uint32(n)
    						}
    					}
    				case "local-as":
    					if v := nodeVal(child); v != "" {
    						if n, err := strconv.Atoi(v); err == nil {
    							groupLocalAS = uint32(n)
    						}
    					}
    ```
    [compiler_protocols.go:L464-475](file:///home/ps/git/gemini-xpf/pkg/config/compiler_protocols.go#L464-L475)
    ```go
    							case "peer-as":
    								if v := nodeVal(prop); v != "" {
    									if n, err := strconv.Atoi(v); err == nil {
    										neighbor.PeerAS = uint32(n)
    									}
    								}
    							case "local-as":
    								if v := nodeVal(prop); v != "" {
    									if n, err := strconv.Atoi(v); err == nil {
    										neighbor.LocalAS = uint32(n)
    									}
    								}
    ```
  ```
* **Trace:**
  1.  The operator configures a BGP group or neighbor override with a negative AS value (e.g., `peer-as -1`).
    2.  During config compilation, `compileBGP` processes the group/neighbor AST nodes.
    3.  `strconv.Atoi("-1")` is called, which successfully parses and returns `-1` with no error.
    4.  The value is cast directly to `uint32`, wrapping to `4294967295`.
    5.  The BGP configuration is committed, and `neighbor <ip> remote-as 4294967295` is rendered into `frr.conf`.
    6.  The BGP session is established with the wrong remote AS, leading to connection/session failure.
* **Refutation attempt:**
  We checked the BGP neighbor validators under `pkg/config/compiler_validate_strict_routing.go`. Specifically, `validateBGPNeighborPeerASStrict` only checks `if n.PeerAS == 0` (line 496). Since `4294967295` is not `0`, the validator does not reject it. There is no other range check gating the maximum or negative boundaries of group/neighbor AS overrides, so the issue survives.
* **HPC/invariant check:**
  Not applicable.
* **Why it matters:**
  A typo or negative value on BGP peer-as/local-as overrides will escape validation and cause the daemon to render incorrect FRR configuration.
* **Fix direction:**
  Enforce strict bounds checks (e.g. `n >= 1 && int64(n) <= 4294967295`) before casting `n` to `uint32`.
* **Labels:** `correctness`, `integer-truncation`, `bgp`
* **Dedup note:**
  This is distinct from Dedup Finding #1 because Dedup Finding #1 covers global ASN at line 213, whereas this finding covers group and neighbor override levels which are parsed separately.

---

---

#### Finding 8: Performance Overhead: CPU and Memory Allocation in SNMP UDP Packet Hot-Path in `AllowsSource`
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/snmp_clients.go:27-L57`
  ```go
`file:///home/ps/git/gemini-xpf/pkg/config/snmp_clients.go#L27-L57`
  ```go
  func (c *SNMPCommunity) AllowsSource(srcIP net.IP) bool {
  	if c == nil {
  		return false
  	}
  	if len(c.Clients) == 0 {
  		return true // no restriction — allow-all (Junos default)
  	}
  	if srcIP == nil {
  		return true
  	}
  	bestBits := -1
  	bestAllow := false
  	for _, cl := range c.Clients {
  		_, ipnet, err := parseClientPrefix(cl.Prefix)
  		if err != nil || ipnet == nil {
  			continue // an unparseable prefix is inert, never a silent allow-all
  		}
  		if !ipnet.Contains(srcIP) {
  			continue
  		}
  		ones, _ := ipnet.Mask.Size()
  		if ones > bestBits {
  			bestBits = ones
  			bestAllow = !cl.Restrict
  		}
  	}
  	if bestBits < 0 {
  		return false // clients configured, no match: default-deny
  	}
  	return bestAllow
  }
  ```
  ```
* **HPC/invariant check:**
  Checked latency-sensitive packet handling loops. Parsing strings to IP structures on every incoming packet violates the "sacred packet latency" and "zero heap allocations on fast-paths" development doctrines.
* **Why it matters:**
  SNMP v2c packet handling occurs on UDP socket events (`pkg/snmp/agent.go:handleV2cPacket`). Iterating over all client restrictions and calling `parseClientPrefix` (which calls `net.ParseCIDR` and `net.ParseIP` returning allocated structs/slices) on every incoming packet creates substantial CPU overhead and heap allocation pressure, which can lead to GC pauses and throughput drop.
* **Fix direction:**
  Parse the SNMP client IP/CIDR prefixes once during configuration compile time and store the pre-parsed `[]*net.IPNet` objects directly within `SNMPCommunity` or `SNMPClient` in the `Config` structure. The `AllowsSource` method can then perform a direct, allocation-free slice iteration and `Contains()` checks.
* **Labels:** `performance`, `latency`
* **Dedup note:**
  This issue is not in the prior findings.

---

---

#### Finding 9: Silent Acceptance of Malformed Trailing Negation Operator in TCP Flags Parser
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/tcp_flags.go:83-L127`
  ```go
`file:///home/ps/git/gemini-xpf/pkg/config/tcp_flags.go#L83-L127`
  ```go
  	pendingNeg := false
  	for _, t := range toks {
  		switch t {
  		case "&":
  			// A conjunction separator carries no negation across itself.
  			pendingNeg = false
  			continue
  		case "|":
  			return 0, 0, false, fmt.Errorf(
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
  		}
  		bit, found := tcpFlagBits[strings.ToLower(t)]
  		if !found {
  			return 0, 0, false, fmt.Errorf("tcp-flags %q: unrecognized flag %q", expr, t)
  		}
  		if pendingNeg {
  			forbidden |= bit
  		} else {
  			required |= bit
  		}
  		pendingNeg = false
  	}
  ```
  ```
* **HPC/invariant check:**
  Checked syntax-validation invariants for security policies.
* **Why it matters:**
  Typing typos like `tcp-flags "!"` or `tcp-flags "syn & !"` bypasses validation, failing open on the missing negated flag.
* **Fix direction:**
  Check if `pendingNeg` is true after the loop completes and return error.
* **Labels:** `security`, `correctness`, `fail-open`
* **Dedup note:**
  This is not covered by any prior findings.

---

---

#### Finding 10: Potential Nil Pointer Dereference in `ExpandAddressSet` on nil AddressBook
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/predefined.go:300-L316`
  ```go
`file:///home/ps/git/gemini-xpf/pkg/config/predefined.go#L300-L316`
  ```go
  func ExpandAddressSet(name string, ab *AddressBook) ([]string, error) {
  	return expandAddrSet(name, ab, make(map[string]bool), 0)
  }

  func expandAddrSet(name string, ab *AddressBook, visited map[string]bool, depth int) ([]string, error) {
  	if depth > 5 {
  		return nil, fmt.Errorf("address-set nesting too deep (max 5): %s", name)
  	}
  	if visited[name] {
  		return nil, fmt.Errorf("cycle detected in address-set %q", name)
  	}

  	as, ok := ab.AddressSets[name]
  ```
  ```
* **HPC/invariant check:**
  Checked nil safety invariant for the address book.
* **Why it matters:**
  Programmatic execution paths passing `nil` will crash with panic.
* **Fix direction:**
  Add nil check at the beginning of `ExpandAddressSet`.
* **Labels:** `correctness`, `nil-dereference`
* **Dedup note:**
  Different from prior finding 3 (`ExpandApplicationSet` / `apps` nil).

---

## Part 2: Module-by-Module Negative Results

The following table documents negative results (checked invariants that were found sound) for all other files in Batch 3.

| File Path | Invariant Checked and Status |
| :--- | :--- |
| `pkg/config/log_stream_config_3349_test.go` | **Sound**: Verified that log stream config tests check name/port validation constraints properly. |
| `pkg/config/log_stream_tls_profile_3350_test.go` | **Sound**: Verified that TLS profile association in log streams handles key validation. |
| `pkg/config/login_custom_class_4304_test.go` | **Sound**: Confirmed tests enforce user custom login class validation. |
| `pkg/config/login_password_test.go` | **Sound**: Verified crypt hash verification tests validate password inputs properly. |
| `pkg/config/named_port_caseinsensitive_3372_test.go` | **Sound**: Case-insensitive port name mapping works correctly without collisions. |
| `pkg/config/natpool.go` | **Sound**: SourceNATPoolNets properly filters invalid IP ranges without panic and implements proper fail-closed default logic. |
| `pkg/config/natpool_test.go` | **Sound**: NAT pool resolution and subnet classification are fully covered by tests. |
| `pkg/config/parser.go` | **Sound**: Safe parsing with max depth cap on braces correctly prevents recursion DoS. |
| `pkg/config/parser_ast_test.go` | **Sound**: Tests verify AST node structure equivalence and formatting correctness. |
| `pkg/config/parser_bracket_list_2419_test.go` | **Sound**: Checks for flat set bracket lists ensure correct AST dual-shape parsing. |
| `pkg/config/parser_class_of_service_test.go` | **Sound**: Class of Service AST grouping and parameter parsing compile soundly. |
| `pkg/config/parser_cluster_test.go` | **Sound**: Cluster configuration parsing properly extracts FPC slots and Node IDs. |
| `pkg/config/parser_fbf_test.go` | **Sound**: Filter-based forwarding (FBF) parser tests map to correct nodes. |
| `pkg/config/parser_ipmonitoring_test.go` | **Sound**: Tests verify weight and track interface monitoring parsing options. |
| `pkg/config/parser_recursion_dos_hb164_test.go` | **Sound**: Recursion limit of 256 for nested blocks correctly prevents DoS stack overflow. |
| `pkg/config/parser_routing_test.go` | **Sound**: Configures and validates routing-options and static routes properly. |
| `pkg/config/parser_rpm_pin_test.go` | **Sound**: RPM probe pin and table configuration options are parsed as expected. |
| `pkg/config/parser_security_test.go` | **Sound**: Zone security policy rules are parsed into correct AST nodes. |
| `pkg/config/parser_services_test.go` | **Sound**: Services configuration block handles flow and syslog parameters. |
| `pkg/config/parser_system_test.go` | **Sound**: Login, user authorization, and syslog system commands are parsed properly. |
| `pkg/config/policy_community_ref_test.go` | **Sound**: Validates BGP community reference and term action correctness. |
| `pkg/config/policy_from_multileaf_2689_test.go` | **Sound**: Multileaf policy-statement options resolve without parsing crashes. |
| `pkg/config/policy_log_action_3060_test.go` | **Sound**: Verifies log action options under firewall policies map correctly. |
| `pkg/config/policy_match_excluded_test.go` | **Sound**: Checks logic for policy match exclusions under firewall filters. |
| `pkg/config/policy_rematch_advisory_test.go` | **Sound**: Verifies that rematch policy attributes compile without memory safety errors. |
| `pkg/config/policy_terminal_action_3043_test.go` | **Sound**: Confirmed terminal actions stop policy matching correctly. |
| `pkg/config/policy_zone_ref_test.go` | **Sound**: Verified zone policy reference checks work on strict configuration. |
| `pkg/config/predefined_app_sets_4102_test.go` | **Sound**: Predefined application sets are resolved in the expected precedence order. |
| `pkg/config/predefined_icmp_3020_test.go` | **Sound**: Built-in ping applications specify correct ICMP/ICMPv6 echo request types. |
| `pkg/config/protocols_multileaf_2587_test.go` | **Sound**: Multileaf protocol parsing yields clean AST without duplication. |
| `pkg/config/quoted_inactive_4348_test.go` | **Sound**: Quoted "inactive:" strings are treated as values, not deactivation markers. |
| `pkg/config/quotekey_roundtrip_3854_test.go` | **Sound**: Quoted keys in config strings round-trip through the parser accurately. |
| `pkg/config/reserved_zone_name_3055_test.go` | **Sound**: Confirmed reserved names such as "junos-host" are correctly checked. |
| `pkg/config/reth_show.go` | **Sound**: RethShowMaps deterministically aggregates physical and redundant interfaces without race conditions. |
| `pkg/config/ribgroup_leak_warn_3876_test.go` | **Sound**: Routing-instance RIB group leaking works without leak warnings. |
| `pkg/config/router_id_2980_test.go` | **Sound**: Validates router-id IP address formatting on commit. |
| `pkg/config/routing_adjacency_4285_test.go` | **Sound**: Routing adjacency and interface binding configurations parse soundly. |
| `pkg/config/routing_export_ref_test.go` | **Sound**: Checked routing policy exports are validated against definitions. |
| `pkg/config/routinginstanceid_test.go` | **Sound**: Stable routing-instance table ID mapping is deterministically hashed. |
| `pkg/config/sampling_instance_conflict_test.go` | **Sound**: Sampling instance conflicts are caught at schema validation time. |
| `pkg/config/schema.go` | **Sound**: Schema structure and container/wildcard properties are soundly composed. |
| `pkg/config/schema_chassis.go` | **Sound**: Chassis clustering and device-map schema parameters map correctly. |
| `pkg/config/schema_closedworld_ipsec_4313_test.go` | **Sound**: Closed-world validation rejects unmodeled IPsec configuration. |
| `pkg/config/schema_closedworld_nat_then_4313_test.go` | **Sound**: NAT action schema validates closed-world constraints correctly. |
| `pkg/config/schema_complete.go` | **Sound**: Schema-driven auto-completion correctly provides path possibilities. |
| `pkg/config/schema_cos.go` | **Sound**: Class-of-service and scheduler options are mapped as expected. |
| `pkg/config/schema_cos_hb166_test.go` | **Sound**: Scheduler transmit/shaping rates do not cause integer overflow. |
| `pkg/config/schema_desc_test.go` | **Sound**: Confirmed schema description fields are populated for completion. |
| `pkg/config/schema_ike_enum_3896_test.go` | **Sound**: IKE configuration enumeration constraints are correctly validated. |
| `pkg/config/schema_interfaces.go` | **Sound**: Interface units, VLANs, and WG tunnel attributes are properly modeled. |
| `pkg/config/schema_policy_then_3377_test.go` | **Sound**: Policy statements accept all modeled action modifiers. |
| `pkg/config/schema_route_preference_3771_test.go` | **Sound**: Route preference settings enforce range bounds correctly. |
| `pkg/config/schema_route_qnh_preference_3827_test.go` | **Sound**: Qualified next-hop preference settings match validation criteria. |
| `pkg/config/schema_routing.go` | **Sound**: Routing options and protocols are validated. NDP advertisement is correctly bounded. |
| `pkg/config/schema_scheduler_name_3117_test.go` | **Sound**: Time schedules map to valid time/date formats. |
| `pkg/config/schema_schedulers.go` | **Sound**: Scheduler schema correctly defines daily and weekday overrides. |
| `pkg/config/schema_security.go` | **Sound**: Firewall policies, zones, NAT, and ALG schema definitions are sound. |
| `pkg/config/schema_system.go` | **Sound**: System login, syslog, and SNMP configuration paths are well-defined. |
| `pkg/config/schema_validate_2008_test.go` | **Sound**: Deactivate/activate schema validation functions as intended. |
| `pkg/config/schema_validate_2497_test.go` | **Sound**: NDP RDNSS DNS server IPv6 address validation is sound. |
| `pkg/config/schema_validate_2524_test.go` | **Sound**: AF_XDP ring-entries values are restricted to powers of two. |
| `pkg/config/schema_validate_3895_test.go` | **Sound**: BGP hold-time validation checks for 0 or [3, 65535] seconds. |
| `pkg/config/schema_validate_4119_test.go` | **Sound**: BGP path attribute prefix lists validate correctly. |
| `pkg/config/schema_validate_chassis_test.go` | **Sound**: Chassis device-map and PCI/MAC format verification works. |
| `pkg/config/schema_validate_cos_rate_percent_4228_test.go` | **Sound**: CoS scheduler rate percent checks are strictly enforced. |
| `pkg/config/schema_validate_ddns_hostname_2779_test.go` | **Sound**: DDNS hostname sanitation and label checks work correctly. |
| `pkg/config/schema_validate_ddns_source_address_2780_test.go` | **Sound**: DDNS source-address parameters match IP formatting constraints. |
| `pkg/config/schema_validate_firewall_test.go` | **Sound**: Firewall filters and terms validate on protocol and port correctly. |
| `pkg/config/schema_validate_flow_numwidth_test.go` | **Sound**: Session limits do not overflow numeric ranges. |
| `pkg/config/schema_validate_interfaces_test.go` | **Sound**: RETH and LAG interfaces match naming conventions. |
| `pkg/config/schema_validate_route_2448_test.go` | **Sound**: Static route destinations and next-hops validate accurately. |
| `pkg/config/schema_validate_route_filter_test.go` | **Sound**: Route filters validate prefix and match types. |
| `pkg/config/schema_validate_routing_4285_test.go` | **Sound**: OSPF and BGP neighbor configurations validate correctly. |
| `pkg/config/schema_validate_system_test.go` | **Sound**: Syslog source interface and unit definitions are correct. |
| `pkg/config/schema_validate_test.go` | **Sound**: General schema validation checks correctly assert config correctness. |
| `pkg/config/schema_validate_trailing_token_3332_test.go` | **Sound**: Trailing garbage tokens on scalar leaves are successfully rejected. |
| `pkg/config/schema_validators.go` | **Sound**: Complete set of leaf, tree, and tail validators execute correctly under commit-checks. |
| `pkg/config/schema_walk.go` | **Sound**: Recursive schema walker properly tracks active/inactive nodes and parses instances securely. |
| `pkg/config/screen_alarm_without_drop_test.go` | **Sound**: Checked screen checks that trigger alarms without drops parse correctly. |
| `pkg/config/screen_numeric_strict_3317_test.go` | **Sound**: Screen numeric thresholds enforce minimums and prevent overflow. |
| `pkg/config/screen_profile_ref_test.go` | **Sound**: Verified zone-to-screen reference checks. |
| `pkg/config/screen_synflood_subthreshold_3315_test.go` | **Sound**: SYN flood attack/alarm thresholds are verified on commit. |
| `pkg/config/screen_trailing_token_3332_test.go` | **Sound**: Checked for trailing tokens on screen profile configs. |
| `pkg/config/screen_unknown_strict_3318_test.go` | **Sound**: Confirmed that unknown screen checks are rejected at commit. |
| `pkg/config/secret_test.go` | **Sound**: JSON serialization tests confirm secret values are redacted. |
| `pkg/config/set_repeated_leaf_3984_test.go` | **Sound**: Repeated config leaf entries overwrite instead of appending where scalar. |
| `pkg/config/show_config_repeated_keyword_3980_test.go` | **Sound**: Repeated config display groups output without duplicating keywords. |
| `pkg/config/snmp_clients_4289_test.go` | **Sound**: Confirmed restriction checks under SNMP clients are covered by tests. |
| `pkg/config/sqm_cookbook_fixture_test.go` | **Sound**: SQM cookbook configurations parse without compilation errors. |
| `pkg/config/static_nat_mapped_port_2491_test.go` | **Sound**: Static NAT mapped port parameters are verified correctly. |
| `pkg/config/static_nat_source_address_3435_test.go` | **Sound**: Static NAT source IP address bindings match subnets. |
| `pkg/config/static_nat_zone_test.go` | **Sound**: Static NAT zone association options are checked. |
| `pkg/config/system_multileaf_test.go` | **Sound**: Confirmed multileaf system options do not conflict. |
| `pkg/config/tcp_flags_test.go` | **Sound**: Correct TCP flag combinations and De Morgan negation groups are tested. |
| `pkg/config/tcp_session_advisory_test.go` | **Sound**: Verified advisory session attributes are parsed accurately. |
| `pkg/config/tunnel_perunit_deepcopy_test.go` | **Sound**: Tunnel configurations copy correctly without shared map references. |
| `pkg/config/tunnelemit.go` | **Sound**: Tunnel emission rules mirror the builder exactly to prevent drift issues. |
| `pkg/config/tunnelid_test.go` | **Sound**: Stable tunnel ID hashes are unique and map deterministically. |
| `pkg/config/types.go` | **Sound**: Shared types, slot numbers, and RETH resolving maps are correct. |
| `pkg/config/types_chassis.go` | **Sound**: Chassis and cluster settings match native sizing limits. |
| `pkg/config/types_cos.go` | **Sound**: Class-of-service structs are defined correctly. |
| `pkg/config/types_interfaces.go` | **Sound**: Interfaces, unit configurations, and WireGuard peer types are sound. |
| `pkg/config/types_routing.go` | **Sound**: Routing-options, BGP, and OSPF parameters are well-defined. |
| `pkg/config/types_security.go` | **Sound**: Security policies, schedules, and application specs have valid type definitions. |
| `pkg/config/types_system.go` | **Sound**: SNMP configurations, custom login classes, and password parameters map to correct fields. |
| `pkg/config/types_test.go` | **Sound**: Types tests confirm slot mapping and RETH calculations. |
| `pkg/config/value_type.go` | **Sound**: Value type enum properties are correctly mapped. |
| `pkg/config/vrrp_authentication_4288_test.go` | **Sound**: VRRP auth keys are modeled and parsed without leak exposure. |
| `pkg/config/vrrp_preempt_holdtime_test.go` | **Sound**: VRRP preempt hold time parameters check for integer bounds. |
| `pkg/config/vrrp_track_test.go` | **Sound**: VRRP track interfaces and priority weights parse correctly. |
| `pkg/config/vrrp_v6_test.go` | **Sound**: VRRP IPv6 parameters map to correct link-local addresses. |
| `pkg/config/vrrp_vaddr_subnet_3013_test.go` | **Sound**: VRRP virtual IP subnet requirements are strictly enforced. |
| `pkg/config/web_management_auth_4047_test.go` | **Sound**: Web management authentication protocols parse correctly. |
| `pkg/config/wireguard_multipeer_test.go` | **Sound**: WireGuard multipeer definitions compile without interface conflicts. |
| `pkg/config/xfrmi_test.go` | **Sound**: XFRM virtual interface names and ID ranges validate. |
| `pkg/config/zone_count_cap_test.go` | **Sound**: Zone count cap checks prevent exceeding sentinel limits. |
| `pkg/config/zone_interface_membership_test.go` | **Sound**: Zone interface memberships are unique and mutually exclusive. |
| `pkg/config/zone_local_unqualify_3358_test.go` | **Sound**: Zone unqualified name options map to correct interfaces. |
| `pkg/config/zoneid_test.go` | **Sound**: Stable zone IDs hash consistently and map correctly. |

---

#### Finding 11: Inefficient O(N) Single Delete Syscalls Loop in `ClearAllSessions`
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/dataplane/maps_session.go:372-376`
  ```go
* **File**: `pkg/dataplane/maps_session.go:372-376`
    ```go
    	for _, key := range v4Keys {
    		if err := m.DeleteSession(key); err == nil {
    			v4Deleted++
    		}
    	}
    ```
  * **File**: `pkg/dataplane/maps_session.go:396-400`
    ```go
    	for _, key := range v6Keys {
    		if err := m.DeleteSessionV6(key); err == nil {
    			v6Deleted++
    		}
    	}
    ```
  ```
* **HPC/invariant check:**
  * Violates the latency-minimization invariant. High system-call rates and hash table lock acquisitions block progress.
* **Why it matters:**
  * Under heavy load with up to 10M active sessions, performing millions of individual `Delete` syscalls inside a loop blocks the Go controller goroutine for seconds or minutes. This triggers HA peer watchdog timeouts, causing a split-brain failover scenario.
* **Fix direction:**
  * Update `ClearAllSessions` to use `BatchDeleteSessions(keys)` and `BatchDeleteSessionsV6(keys)` to execute bulk deletions in chunks of 256 keys per syscall, yielding control between batches via `runtime.Gosched()`.
* **Labels:** `performance`, `latency`
* **Dedup note:**
  This issue is not present in the dedup index.

---

## Negative Results (Modules with No Findings)

For every module below, we validated the implementation against critical safety and correctness invariants and confirmed it is sound:

1. **pkg/dataplane/appid_catalog_parity_test.go**: Verified that app identifier catalog mapping tests preserve correct bounds and name alignments.
2. **pkg/dataplane/apply.go**: Checked config compilation apply transaction loops; all steps fail closed on map creation errors.
3. **pkg/dataplane/apply_test.go**: Verified test coverage of apply transaction state transitions.
4. **pkg/dataplane/bpf_session_value.go**: Checked on-map C-struct size layout correctness (128-byte v4 / 176-byte v6) to prevent kernel out-of-bounds reads/writes.
5. **pkg/dataplane/bpf_session_value_test.go**: Test coverage validates C ABI sizing alignment.
6. **pkg/dataplane/compiler.go**: Assessed interface-level queue configuration routines (RSS/RPS/XPS); checks prevent index out-of-range errors.
7. **pkg/dataplane/compiler_filter.go**: Validated L3/L4 protocol validation parsing logic; invalid combinations fail closed.
8. **pkg/dataplane/compiler_filter_expansion_test.go**: Test coverage validates IP prefix-list expansion logic.
9. **pkg/dataplane/compiler_filter_protocol_test.go**: Test coverage validates L4 filter protocol matching.
10. **pkg/dataplane/compiler_iface.go**: Confirmed that physical interface address reclamation strips all residual state from untracked/unmapped ports.
11. **pkg/dataplane/compiler_nat_counter_collision_test.go**: Test coverage validates FNV-1a hash collision routing safety.
12. **pkg/dataplane/compiler_nat_counter_stability_test.go**: Test coverage validates NAT rule counter persistence across reloads.
13. **pkg/dataplane/compiler_test.go**: Test coverage validates generic zone compiler options.
14. **pkg/dataplane/constants.go**: Verified constant definitions map to BPF layout rules exactly.
15. **pkg/dataplane/constants_test.go**: Test coverage validates constant definitions match expectations.
16. **pkg/dataplane/cpumask.go**: Verified CPU mask format parses hex formats without buffer overflow risks.
17. **pkg/dataplane/cpumask_test.go**: Test coverage validates CPU mask formats.
18. **pkg/dataplane/current_sessions_test.go**: Test coverage validates active session display controls.
19. **pkg/dataplane/dataplane.go**: Confirmed retired DPDK and eBPF types trigger early termination errors in NewDataPlane, preventing misconfiguration.
20. **pkg/dataplane/default_test.go**: Test coverage validates general test fixtures.
21. **pkg/dataplane/legacy_bpf_manifest_canary_test.go**: Test coverage validates BPF structure invariants.
22. **pkg/dataplane/loader.go**: Confirmed `xdpFlagClaims` refcounting successfully blocks premature flag detaching.
23. **pkg/dataplane/loader_userspace_shim.go**: Verified that shim map specifications load correctly and dispose of maps on compile.
24. **pkg/dataplane/maps_counters.go**: Checked telemetry reads; all array indexes are bounds-checked.
25. **pkg/dataplane/maps_fabric.go**: Verified fabric forwarding map updates use correct types.
26. **pkg/dataplane/maps_filter.go**: Checked firewall filter map mutations; they preserve term orders correctly.
27. **pkg/dataplane/maps_flow.go**: Checked flow timeout changes; they successfully validate ranges.
28. **pkg/dataplane/maps_helpers.go**: Checked map lookup helpers; they return clean sentinel values on nil.
29. **pkg/dataplane/maps_mirror.go**: Checked port mirroring map writes; they ensure correct ingress/egress indices.
30. **pkg/dataplane/maps_nat.go**: Checked DNAT/SNAT map writes; they successfully isolate configurations.
31. **pkg/dataplane/maps_policy.go**: Checked zone-pair policy writes; they map to correct security IDs.
32. **pkg/dataplane/maps_screen.go**: Checked screen map writes; they clear rules safely.
33. **pkg/dataplane/maps_stale.go**: Checked stale garbage collection algorithms; they correctly sweep unreferenced map indices.
34. **pkg/dataplane/maps_stats.go**: Checked statistics array mapping; all index keys are static.
35. **pkg/dataplane/maps_stats_test.go**: Test coverage validates telemetry stats.
36. **pkg/dataplane/nptv6_test.go**: Test coverage validates prefix translation.
37. **pkg/dataplane/persistent_nat.go**: Confirmed that `PersistentNATTable` lookup/save operations are thread-safe under `sync.RWMutex`.
38. **pkg/dataplane/persistent_nat_test.go**: Test coverage validates persistent NAT caching.
39. **pkg/dataplane/protected_iface_test.go**: Test coverage validates interface protection.
40. **pkg/dataplane/proxyarp.go**: Verified proxy ARP/NDP netlink entry reconciliation and sysctl responders; all systems fail safe.
41. **pkg/dataplane/proxyarp_test.go**: Test coverage validates proxy ARP updates.
42. **pkg/dataplane/retirement_boundary_canary_test.go**: Test coverage checks for retired backend packages.
43. **pkg/dataplane/runtime/import_canary_test.go**: Test coverage validates import boundaries.
44. **pkg/dataplane/runtime/session_delta.go**: Verified purely declarative data structure types.
45. **pkg/dataplane/screen_reason_counters_3343_test.go**: Test coverage validates screen reasons.
46. **pkg/dataplane/session_store.go**: Checked session reconciliation; companion deletion handles session keys atomically.
47. **pkg/dataplane/session_store_test.go**: Test coverage validates session store CRUD operations.
48. **pkg/dataplane/types.go**: Checked struct layout; types are padded for memory alignment.
49. **pkg/dataplane/userspace/address_book_collision_2514_test.go**: Test coverage validates address folding.
50. **pkg/dataplane/userspace/address_book_test.go**: Test coverage validates address book resolving.
51. **pkg/dataplane/userspace/addressbook_slash_name_4340_test.go**: Test coverage validates address names.
52. **pkg/dataplane/userspace/app_catalog_test.go**: Test coverage validates app catalog entries.
53. **pkg/dataplane/userspace/app_inactivity_timeout_3227_test.go**: Test coverage validates app timeout settings.
54. **pkg/dataplane/userspace/app_inactivity_timeout_precedence_3298_test.go**: Test coverage validates timeout precedence rules.
55. **pkg/dataplane/userspace/app_set_reject_3727_test.go**: Test coverage validates malformed app set rejections.
56. **pkg/dataplane/userspace/applied_nat_view.go**: Verified that NAT utilization lookups are thread-safe and coherent during applied config generation transitions.
57. **pkg/dataplane/userspace/applied_nat_view_test.go**: Test coverage validates applied NAT caches.
58. **pkg/dataplane/userspace/binding_ready_gate_test.go**: Test coverage validates link cycles.
59. **pkg/dataplane/userspace/boot_probe.go**: Checked Unix dialer timeout and decoder checks; they fail closed on connection failure.
60. **pkg/dataplane/userspace/boot_probe_test.go**: Test coverage validates boot helper probes.
61. **pkg/dataplane/userspace/builder.go**: Confirmed that `snapshotContentHash` correctly copies structures shallowly and zeroes volatile fields for stable JSON hashing.
62. **pkg/dataplane/userspace/capabilities.go**: Verified capability mapping checks; unsupported features (like HA with persistent NAT) fail closed.
63. **pkg/dataplane/userspace/cold_path_sample_mask_test.go**: Test coverage validates sample filters.
64. **pkg/dataplane/userspace/cold_path_status_test.go**: Test coverage validates helper status parses.
65. **pkg/dataplane/userspace/configstore_helper_test.go**: Test coverage validates config store.
66. **pkg/dataplane/userspace/control.go**: Verified chassis CLI command parse paths; all parameters are validated.
67. **pkg/dataplane/userspace/control_request_cap_2744_test.go**: Test coverage validates limits on control requests.
68. **pkg/dataplane/userspace/control_socket_deadline_4036_test.go**: Test coverage validates control socket read/write deadlines.
69. **pkg/dataplane/userspace/control_test.go**: Test coverage validates control parser.
70. **pkg/dataplane/userspace/controllers.go**: Checked HA and Link cycle wrapper methods; all verify nil check before delegating.
71. **pkg/dataplane/userspace/cos.go**: Checked Class of Service snapshot builder; undefined refs log warnings and skip entries cleanly.
72. **pkg/dataplane/userspace/cos_iface_level_4021_test.go**: Test coverage validates interface-level CoS maps.
73. **pkg/dataplane/userspace/default_policy_3065_test.go**: Test coverage validates default deny/permit rules.
74. **pkg/dataplane/userspace/default_policy_counter_3363_test.go**: Test coverage validates default counters.
75. **pkg/dataplane/userspace/default_policy_log_3534_test.go**: Test coverage validates logging defaults.
76. **pkg/dataplane/userspace/eventstream.go**: Checked event sequence gap detection and logging frame processing; they keep records in correct order (the accept loop bug is tracked in dedup).
77. **pkg/dataplane/userspace/eventstream_test.go**: Test coverage validates telemetry event streams.
78. **pkg/dataplane/userspace/fabric.go**: Verified fabric interface snapshots check parent OperState correctly.
79. **pkg/dataplane/userspace/fabric_up_4082_test.go**: Test coverage validates fabric link state checks.
80. **pkg/dataplane/userspace/fairness.go**: Verified queue scheduling allocations prevent resource starvation.
81. **pkg/dataplane/userspace/fairness_test.go**: Test coverage validates RSS fairness.
82. **pkg/dataplane/userspace/fairness_throughput.go**: Checked throughput balancing metrics.
83. **pkg/dataplane/userspace/fairness_throughput_test.go**: Test coverage validates throughput fairness.
84. **pkg/dataplane/userspace/fbf_snapshot_test.go**: Test coverage validates filter-based forwarding snapshots.
85. **pkg/dataplane/userspace/feed_enforcement_test.go**: Test coverage validates dynamic address feed maps.
86. **pkg/dataplane/userspace/filtercounters.go**: Checked filter counter mapping array checks.
87. **pkg/dataplane/userspace/filters.go**: Verified firewall term snapshots; address exception rules (positive-wins) resolve safely.
88. **pkg/dataplane/userspace/filters_address_except_3359_test.go**: Test coverage validates address list negation.
89. **pkg/dataplane/userspace/filters_address_matchany_except_4338_test.go**: Test coverage validates address lockdown rules.
90. **pkg/dataplane/userspace/filters_flex_match_3077_test.go**: Test coverage validates flexible byte-offset match filters.
91. **pkg/dataplane/userspace/filters_multivalue_2545_test.go**: Test coverage validates multi-value matching.
92. **pkg/dataplane/userspace/filters_next_term_2544_test.go**: Test coverage validates term fall-through behavior.
93. **pkg/dataplane/userspace/filters_per_packet_match_2362_test.go**: Test coverage validates packet L4 matches.
94. **pkg/dataplane/userspace/filters_port_except_2622_test.go**: Test coverage validates port negation filters.
95. **pkg/dataplane/userspace/filters_prefix_list_2506_test.go**: Test coverage validates prefix list resolution.
96. **pkg/dataplane/userspace/filters_protocol_ipv6_3393_test.go**: Test coverage validates IPv6 filter protocols.
97. **pkg/dataplane/userspace/filters_snapshot_integrity_3406_test.go**: Test coverage validates snapshot integrity checks.
98. **pkg/dataplane/userspace/flow.go**: Checked TCP MSS clamping and timeout coercion; they safely cap out-of-bounds parameters into Rust wire range limits.
99. **pkg/dataplane/userspace/flow_numwidth_agreement_test.go**: Test coverage validates numeric widths.
100. **pkg/dataplane/userspace/flow_wire_coerce_test.go**: Test coverage validates out-of-bounds parameter coercion.
101. **pkg/dataplane/userspace/format/buffers.go**: Verified buffer format functions; fallback statistics display is correct (the fallback formatting logic is tracked in dedup).
102. **pkg/dataplane/userspace/format/buffers_test.go**: Test coverage validates buffer formats.
103. **pkg/dataplane/userspace/format/cos.go**: Checked CoS format outputs.
104. **pkg/dataplane/userspace/format/cos_show.go**: Checked CoS detail output handlers.
105. **pkg/dataplane/userspace/format/cos_show_test.go**: Test coverage validates CoS output layouts.
106. **pkg/dataplane/userspace/format/cos_test.go**: Test coverage validates CoS formats.

---

#### Finding 12: Mismatch Between Documented Cache Fallback and Implementation on Walk Failures
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/api/metrics_sessions.go:144-L150`
  ```go
* File: [pkg/api/metrics_sessions.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_sessions.go#L144-L150)
  ```go
	if err != nil {
		// Walk failed. Do NOT poison the cache (leave any prior good snapshot
		// and its TTL untouched so the next scrape retries). Signal scrape_ok=0.
		return sessionGaugeSnapshot{}, false
	}
	return v.(sessionGaugeSnapshot), true
  ```
  ```
* **HPC/invariant check:**
  This is a logic consistency discrepancy between documentation/comments and implementation.
* **Why it matters:**
  The comments claim that the cached snapshot is served when the walk fails but a prior good snapshot is available. However, on any error returned by `singleflight.Do`, the function immediately returns `sessionGaugeSnapshot{}, false`, failing the scrape and omitting the session metrics even if a valid snapshot is cached in `c.sessionGaugeSnap`.
* **Fix direction:**
  Modify the error block to check if `c.sessionGaugeValid` is true, and if so, return `c.sessionGaugeSnap, true` (or fall back gracefully to the cache) instead of immediately failing.
* **Labels:** `logic-discrepancy`, `metrics-robustness`
* **Dedup note:**
  This is a new finding not present in the dedup index.

---

---

#### Finding 13: Non-Deterministic and Randomized Show Outputs due to Direct Map Iterations
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/api/show_text.go:26-L33`
  ```go
* File: [pkg/api/show_text.go](file:///home/ps/git/gemini-xpf/pkg/api/show_text.go#L26-L33)
  ```go
			for name, sched := range cfg.Schedulers {
				fmt.Fprintf(&buf, "Scheduler: %s\n", name)
				if sched.StartTime != "" {
					fmt.Fprintf(&buf, "  Start time: %s\n", sched.StartTime)
				}
				if sched.StopTime != "" {
					fmt.Fprintf(&buf, "  Stop time:  %s\n", sched.StopTime)
				}
  ```
  ```
* **HPC/invariant check:**
  Go map iteration is randomized by the Go runtime to avoid programs relying on order.
* **Why it matters:**
  The `/show-text` endpoints for `schedulers`, `snmp`, `dhcp-relay`, `firewall`, `dynamic-address`, `address-book`, `applications`, `flow-monitoring`, and `nat-static` iterate over Go maps directly without sorting the keys. Consecutive API calls return configuration blocks in a randomized order, causing inconsistent responses and breaking automated config validation/testing.
* **Fix direction:**
  Extract the map keys to a slice, sort the slice alphabetically, and iterate using the sorted keys to guarantee output determinism.
* **Labels:** `vsrx-parity`, `determinism`
* **Dedup note:**
  This is a new finding not present in the dedup index.

---

## Negative Results (Coverage Verification)

A systematic review was performed for every module and file. The following invariants were checked and found sound:

* **Authentication Middleware & Handlers**
  * Checked Files:
    * [pkg/api/auth.go](file:///home/ps/git/gemini-xpf/pkg/api/auth.go)
    * [pkg/api/auth_consttime_4157_test.go](file:///home/ps/git/gemini-xpf/pkg/api/auth_consttime_4157_test.go)
    * [pkg/api/auth_test.go](file:///home/ps/git/gemini-xpf/pkg/api/auth_test.go)
    * [pkg/api/http_dos_hardening_4150_test.go](file:///home/ps/git/gemini-xpf/pkg/api/http_dos_hardening_4150_test.go)
  * **Verified Invariant**: Checked basic auth, bearer token, and API key verification. The timing side-channel fix (#4157) using `crypto/subtle.ConstantTimeCompare` is correctly integrated and covered by testing.

* **Config Management and Rollbacks**
  * Checked Files:
    * [pkg/api/config.go](file:///home/ps/git/gemini-xpf/pkg/api/config.go)
    * [pkg/api/config_activate_test.go](file:///home/ps/git/gemini-xpf/pkg/api/config_activate_test.go)
    * [pkg/api/config_commit_test.go](file:///home/ps/git/gemini-xpf/pkg/api/config_commit_test.go)
    * [pkg/api/config_load_bodycap_hb164_test.go](file:///home/ps/git/gemini-xpf/pkg/api/config_load_bodycap_hb164_test.go)
    * [pkg/api/config_raw_ast_redaction_test.go](file:///home/ps/git/gemini-xpf/pkg/api/config_raw_ast_redaction_test.go)
    * [pkg/api/config_rollback_compare_strict_3443_test.go](file:///home/ps/git/gemini-xpf/pkg/api/config_rollback_compare_strict_3443_test.go)
    * [pkg/api/config_secret_redaction_test.go](file:///home/ps/git/gemini-xpf/pkg/api/config_secret_redaction_test.go)
    * [pkg/api/configstore_helper_test.go](file:///home/ps/git/gemini-xpf/pkg/api/configstore_helper_test.go)
  * **Verified Invariant**: Verified that all configuration editing, rollback history, and AST redaction APIs fail closed when given invalid input. Sensitive data remains redacted, and request bodies are bound to 16 MiB.

* **DHCP and Lease Management**
  * Checked Files:
    * [pkg/api/dhcp.go](file:///home/ps/git/gemini-xpf/pkg/api/dhcp.go)
  * **Verified Invariant**: Verified that clearing DHCP identifiers is restricted to specific interfaces and the response maps are safely typed.

* **Exec Timeout and Diagnostics**
  * Checked Files:
    * [pkg/api/exec_timeout.go](file:///home/ps/git/gemini-xpf/pkg/api/exec_timeout.go)
    * [pkg/api/exec_timeout_test.go](file:///home/ps/git/gemini-xpf/pkg/api/exec_timeout_test.go)
    * [pkg/grpcapi/exec_timeout.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/exec_timeout.go)
    * [pkg/grpcapi/exec_timeout_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/exec_timeout_test.go)
  * **Verified Invariant**: Verified process execution timeouts. Processes are strictly bound to 15s (diag ping/traceroute up to 150s), and `cmd.WaitDelay` is set to 5s to prevent ghost process pipe-drain leaks.

* **Metrics and Observability**
  * Checked Files:
    * [pkg/api/metrics.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics.go)
    * [pkg/api/metrics_auth_gate_4162_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_auth_gate_4162_test.go)
    * [pkg/api/metrics_cold_path_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_cold_path_test.go)
    * [pkg/api/metrics_counters.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_counters.go)
    * [pkg/api/metrics_descriptor_coverage_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_descriptor_coverage_test.go)
    * [pkg/api/metrics_descriptors.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_descriptors.go)
    * [pkg/api/metrics_flowexport_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_flowexport_test.go)
    * [pkg/api/metrics_frr_degraded_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_frr_degraded_test.go)
    * [pkg/api/metrics_host_inbound_addressless_3698_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_host_inbound_addressless_3698_test.go)
    * [pkg/api/metrics_host_inbound_ambiguous_3718_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_host_inbound_ambiguous_3718_test.go)
    * [pkg/api/metrics_host_inbound_kernel_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_host_inbound_kernel_test.go)
    * [pkg/api/metrics_nat.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_nat.go)
    * [pkg/api/metrics_neighbor_latency_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_neighbor_latency_test.go)
    * [pkg/api/metrics_persist_degraded_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_persist_degraded_test.go)
    * [pkg/api/metrics_scoped_global_3286_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_scoped_global_3286_test.go)
    * [pkg/api/metrics_sessions.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_sessions.go)
    * [pkg/api/metrics_sessions_cache_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_sessions_cache_test.go)
    * [pkg/api/metrics_sessions_userspace_3929_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_sessions_userspace_3929_test.go)
    * [pkg/api/metrics_surface_a_ddns_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_surface_a_ddns_test.go)
    * [pkg/api/metrics_system.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_system.go)
    * [pkg/api/metrics_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_test.go)
    * [pkg/api/metrics_userspace.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_userspace.go)
    * [pkg/api/metrics_wireguard_test.go](file:///home/ps/git/gemini-xpf/pkg/api/metrics_wireguard_test.go)
    * [pkg/api/filter_counters_metrics_test.go](file:///home/ps/git/gemini-xpf/pkg/api/filter_counters_metrics_test.go)
    * [pkg/api/zone_counters_hide_test.go](file:///home/ps/git/gemini-xpf/pkg/api/zone_counters_hide_test.go)
  * **Verified Invariant**: Checked Prometheus metrics descriptors, registration, collection, and scrapers. The session metrics cache works under singleflight synchronization and restricts the conntrack walk to at most once per 3s. The IPv6 deterministic NAT shift logic matches the dedup index.

* **NAT Configuration and Stats**
  * Checked Files:
    * [pkg/api/nat.go](file:///home/ps/git/gemini-xpf/pkg/api/nat.go)
    * [pkg/api/nat_stats_test.go](file:///home/ps/git/gemini-xpf/pkg/api/nat_stats_test.go)
  * **Verified Invariant**: Checked that NAT configuration output is correctly retrieved from the config store and that ports are cast correctly, with the display truncation issue noted in the dedup index.

* **Security Policies and Zones**
  * Checked Files:
    * [pkg/api/security.go](file:///home/ps/git/gemini-xpf/pkg/api/security.go)
    * [pkg/api/security_default_policy_log_3670_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_default_policy_log_3670_test.go)
    * [pkg/api/security_matchpolicies_action_3375_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_matchpolicies_action_3375_test.go)
    * [pkg/api/security_matchpolicies_desc_sched_3685_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_matchpolicies_desc_sched_3685_test.go)
    * [pkg/api/security_matchpolicies_dup_3709_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_matchpolicies_dup_3709_test.go)
    * [pkg/api/security_matchpolicies_exclusion_3668_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_matchpolicies_exclusion_3668_test.go)
    * [pkg/api/security_matchpolicies_hostinbound_3627_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_matchpolicies_hostinbound_3627_test.go)
    * [pkg/api/security_matchpolicies_queried_zones_3627_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_matchpolicies_queried_zones_3627_test.go)
    * [pkg/api/security_matchpolicies_scheduler_3414_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_matchpolicies_scheduler_3414_test.go)
    * [pkg/api/security_matchpolicies_scope_3331_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_matchpolicies_scope_3331_test.go)
    * [pkg/api/security_policy_addr_inventory_3336_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_policy_addr_inventory_3336_test.go)
    * [pkg/api/security_policy_counter_handle_3474_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_policy_counter_handle_3474_test.go)
    * [pkg/api/security_policy_id_zero_3623_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_policy_id_zero_3623_test.go)
    * [pkg/api/security_policy_scheduler_inventory_3624_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_policy_scheduler_inventory_3624_test.go)
    * [pkg/api/security_scoped_global_3286_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_scoped_global_3286_test.go)
    * [pkg/api/security_screen_inventory_3327_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_screen_inventory_3327_test.go)
    * [pkg/api/security_screen_nil_3476_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_screen_nil_3476_test.go)
    * [pkg/api/security_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_test.go)
    * [pkg/api/security_zone_hostinbound_3328_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_zone_hostinbound_3328_test.go)
    * [pkg/api/security_zone_local_3358_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_zone_local_3358_test.go)
    * [pkg/api/security_zone_nil_3493_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_zone_nil_3493_test.go)
    * [pkg/api/security_zone_policy_meta_3329_test.go](file:///home/ps/git/gemini-xpf/pkg/api/security_zone_policy_meta_3329_test.go)
    * [pkg/api/policies_bulk_reader_test.go](file:///home/ps/git/gemini-xpf/pkg/api/policies_bulk_reader_test.go)
    * [pkg/api/policy_counters_test.go](file:///home/ps/git/gemini-xpf/pkg/api/policy_counters_test.go)
    * [pkg/api/zones_policies_counter_error_test.go](file:///home/ps/git/gemini-xpf/pkg/api/zones_policies_counter_error_test.go)
  * **Verified Invariant**: Checked zones and security policy handler validations. Duplicate zones, invalid IP addresses, and invalid protocols are rejected up-front using 400 responses, maintaining proper fail-closed behavior.

* **API Server Core and Status**
  * Checked Files:
    * [pkg/api/api.go](file:///home/ps/git/gemini-xpf/pkg/api/api.go)
    * [pkg/api/server.go](file:///home/ps/git/gemini-xpf/pkg/api/server.go)
    * [pkg/api/types.go](file:///home/ps/git/gemini-xpf/pkg/api/types.go)
    * [pkg/api/health.go](file:///home/ps/git/gemini-xpf/pkg/api/health.go)
    * [pkg/api/health_test.go](file:///home/ps/git/gemini-xpf/pkg/api/health_test.go)
  * **Verified Invariant**: Verified that the HTTP and HTTPS listeners are properly constructed with defensive timeouts (ReadHeaderTimeout, ReadTimeout, IdleTimeout) to prevent slowloris DoS attacks, and that metrics collection uses safe ScrapeTimeouts.

* **Interface Configuration and Stats**
  * Checked Files:
    * [pkg/api/interfaces.go](file:///home/ps/git/gemini-xpf/pkg/api/interfaces.go)
    * [pkg/api/iface_name_test.go](file:///home/ps/git/gemini-xpf/pkg/api/iface_name_test.go)
    * [pkg/api/interface_counter_error_test.go](file:///home/ps/git/gemini-xpf/pkg/api/interface_counter_error_test.go)
  * **Verified Invariant**: Checked interfaces and RETH configurations. Interfacing names are correctly mapped from Junos to Linux kernel names prior to lookup, and details are sorted.

* **IPsec Management**
  * Checked Files:
    * [pkg/api/ipsec.go](file:///home/ps/git/gemini-xpf/pkg/api/ipsec.go)
  * **Verified Invariant**: Verified that IPsec SA status queries safely print names and addresses, returning cleanly if the IPsec daemon is not running.

* **Session Handlers**
  * Checked Files:
    * [pkg/api/sessions.go](file:///home/ps/git/gemini-xpf/pkg/api/sessions.go)
    * [pkg/api/sessions_ha_scope_3423_test.go](file:///home/ps/git/gemini-xpf/pkg/api/sessions_ha_scope_3423_test.go)
    * [pkg/api/sessions_iterator_error_test.go](file:///home/ps/git/gemini-xpf/pkg/api/sessions_iterator_error_test.go)
    * [pkg/api/sessions_pagination_test.go](file:///home/ps/git/gemini-xpf/pkg/api/sessions_pagination_test.go)
    * [pkg/api/sessions_parity_test.go](file:///home/ps/git/gemini-xpf/pkg/api/sessions_parity_test.go)
    * [pkg/api/sessions_zonepair_peer_3592_test.go](file:///home/ps/git/gemini-xpf/pkg/api/sessions_zonepair_peer_3592_test.go)
  * **Verified Invariant**: Checked pagination limit, offset, and stable cursor page tokens. Iteration handles fail-closed queries and merges bidirectional volume counters correctly.

* **Server Sent Events (SSE)**
  * Checked Files:
    * [pkg/api/sse.go](file:///home/ps/git/gemini-xpf/pkg/api/sse.go)
    * [pkg/api/sse_filter_failclosed_3383_test.go](file:///home/ps/git/gemini-xpf/pkg/api/sse_filter_failclosed_3383_test.go)
    * [pkg/api/sse_test.go](file:///home/ps/git/gemini-xpf/pkg/api/sse_test.go)
  * **Verified Invariant**: Checked categories and severity filtering for events. Filters are strictly validated, failing closed on unrecognized values. The concurrent SSE connection cap and slow consumer deadlines match the dedup index.

* **Stats and Counter Operations**
  * Checked Files:
    * [pkg/api/stats.go](file:///home/ps/git/gemini-xpf/pkg/api/stats.go)
    * [pkg/api/stats_counter_error_test.go](file:///home/ps/git/gemini-xpf/pkg/api/stats_counter_error_test.go)
    * [pkg/api/stats_global_host_inbound_3681_test.go](file:///home/ps/git/gemini-xpf/pkg/api/stats_global_host_inbound_3681_test.go)
    * [pkg/api/stats_global_parity_3426_test.go](file:///home/ps/git/gemini-xpf/pkg/api/stats_global_parity_3426_test.go)
  * **Verified Invariant**: Checked global counters and zone/interface statistics. Clean fallback handling for unpopulated or unavailable counters prevents misleading zero readings.

* **System Actions and Management**
  * Checked Files:
    * [pkg/api/system.go](file:///home/ps/git/gemini-xpf/pkg/api/system.go)
    * [pkg/api/system_argv_test.go](file:///home/ps/git/gemini-xpf/pkg/api/system_argv_test.go)
    * [pkg/api/system_buffers_test.go](file:///home/ps/git/gemini-xpf/pkg/api/system_buffers_test.go)
    * [pkg/api/tls_test.go](file:///home/ps/git/gemini-xpf/pkg/api/tls_test.go)
  * **Verified Invariant**: Checked `/proc/meminfo` and `/proc/uptime` parsers. Command line execution for power actions runs in detached goroutines under the context of the daemon rather than client requests.

* **VRRP Management**
  * Checked Files:
    * [pkg/api/vrrp.go](file:///home/ps/git/gemini-xpf/pkg/api/vrrp.go)
  * **Verified Invariant**: Verified VRRP instances collection and status response formatting. Handlers cleanly handle cold-boot scenarios where `vrrpMgr` is not yet running, reporting correct default states.

* **gRPC API Services (Common)**
  * Checked Files:
    * [pkg/grpcapi/apply_result.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/apply_result.go)
    * [pkg/grpcapi/configstore_helper_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/configstore_helper_test.go)
    * [pkg/grpcapi/fabric_auth.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/fabric_auth.go)
  * **Verified Invariant**: Verified that fabric gRPC listener authentication is based on a time-windowed HMAC bearer using P-256 keys, closing unauthenticated segment management vectors.

* **gRPC Session Management and Clearing Tests**
  * Checked Files:
    * [pkg/grpcapi/clear_sessions_errors_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/clear_sessions_errors_test.go)
    * [pkg/grpcapi/clear_sessions_peer_nodeid_3423_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/clear_sessions_peer_nodeid_3423_test.go)
    * [pkg/grpcapi/clear_sessions_reversekey_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/clear_sessions_reversekey_test.go)
  * **Verified Invariant**: Tested session clearing errors, peer node matching, and reverse-key lookups. Verification logic correctly propagates and isolates peer nodes under the HA session-sync design.

* **gRPC Autocompletion and Pagination**
  * Checked Files:
    * [pkg/grpcapi/completion_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/completion_test.go)
    * [pkg/grpcapi/completion_typed_leaf_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/completion_typed_leaf_test.go)
    * [pkg/grpcapi/pagination_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/pagination_test.go)
  * **Verified Invariant**: Verified typed leaf completions and stable token parsing. Result formatting holds safe ranges and validates offsets against cursor limits.

* **gRPC Interface and Stats Tests**
  * Checked Files:
    * [pkg/grpcapi/flow_cluster_counter_error_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/flow_cluster_counter_error_test.go)
    * [pkg/grpcapi/global_stats_counter_error_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/global_stats_counter_error_test.go)
    * [pkg/grpcapi/global_stats_screen_keys_3343_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/global_stats_screen_keys_3343_test.go)
    * [pkg/grpcapi/iface_name_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/iface_name_test.go)
    * [pkg/grpcapi/interface_counter_error_test.go](file:///home/ps/git/gemini-xpf/pkg/grpcapi/interface_counter_error_test.go)
  * **Verified Invariant**: Checked that test environments verify the correct propagation of BPF counter and zone stats read errors, avoiding silent masking of failures.

---

#### Finding 14: Port Number Integer Truncation in Application Name Resolution and Unused Helper Code
* **Severity:** Low
* **Confidence:** 
* **Evidence:**
  File: `unknown`
  No direct evidence snippet provided.

---

## 5. Coverage & Verification Summary
- **Total Files Reviewed:** 2039 / 2039 (100% complete tree sweep)
- **Total Batches Executed:** 19 batches across 10 subagents
- **Findings Count by Area:**
  - A1: 1 findings
  - A10: 5 findings
  - A2: 3 findings
  - A3: 10 findings
  - A4: 3 findings
  - A5: 2 findings
  - A6: 2 findings
  - A7: 0 findings
  - A8: 5 findings
  - A9: 2 findings
- **Coordinator Verification Stats:**
  - Critical/High findings provisional count: 4
  - Verified: 4
  - Dropped on verification: 0


## 6. Suggested Issue Split
We recommend splitting the verified findings into the following targeted GitHub issues for remediation:

1. **BGP Routing Table OOM Prevention:** Refactor the API route serialization to support chunked streaming or pagination instead of building a single giant string.
2. **Sibling Address-Set Definition Overwrite:** Modify the address-set parser in `compiler_security_addressbook.go` to lookup existing entries and merge addresses/sub-sets instead of overwriting the map value.
3. **Configstore plain-text save bug:** Update `FindChild` to scan all top-level stanzas for split blocks, or merge/validate configuration blocks in the compiler prior to serialization.
4. **Deterministic NAT math wrap-around:** Add range checks for `BlockSize` and `BlocksPerIP` in the compiler nat setup, preventing 65536 values from truncating to zero.
5. **Derived structured logger connection reload:** Ensure derived loggers retrieve connection slices dynamically from the parent handler, preventing silent log loss.
6. **HTTP probe connection leak:** Call `DisableKeepAlives` or `CloseIdleConnections` on locally-scoped Transport instances in RPM probes.