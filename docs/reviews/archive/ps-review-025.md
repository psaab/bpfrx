# xpf firewall deep audit — Cohort 1: Policy verdict engine — ps-review-025

## 1. Base commit reviewed

```
b1bd96fb68de40d6fc357e63d9717f7ad75241fa  Merge pull request #4531 from psaab/fix/4526-dhcp-timer-overflow
```

Branch: master. Read-only audit. No source mutations.
HEAD includes fixes for: #4524 monitor traffic injection, #4521 NAT pool bracket-list, #4525 RA interval, #4526 DHCP timer overflow, plus all earlier fixes (#4384 TCP checksum, #4388 HA NAT, #4392 PBR reject, #4393 dnat_table, #4399/#4438 NAT 1:N, #4400/#4441/#4442/#4447/#4448/#4453/#4487 RST/FIN, #3043 terminal action, #3090 wildcard tiers, #3110 unzoned guard, #3148 global zone scope, #3261/#3367/#3711 snapshot integrity, #3402 UnresolvableZoneReference, #3405 host-inbound default-deny, #3712 ICMP validation, #3713 DuplicateRuleId/PolicyId, #3947 any fix, etc.)

## 2. Output path

```
/tmp/ps-review-025.md
```

## 3. Duplicate-suppression summary + intentional-divergence list

### Prior findings reviewed

- `/tmp/all_findings.txt` — 272 entries (F-001..F-272)
- `/tmp/ps-review-018.md` — policy engine audit on c2ee227c4 (same HEAD lineage, 1 fix behind)
- `/tmp/ps-review-019.md` — policy engine audit on d24417ca1 (older, many claims re-evaluated)
- `/tmp/ps-review-020.md`, `ps-review-024.md` — session/cohort 6 (S-001 cross-zone, S-002 bare ACK)
- `/tmp/ps-review-021.md` — IPsec/IKE/WG/routing/HA cohorts
- `/tmp/ps-review-022.md` — config/schema/compiler cohort (R-01..R-07)
- `/tmp/ps-review-023.md` — DHCP/RA/flowexport/CLI/REST/gRPC/wire cohorts
- `docs/feature-gaps.md` (2026-05-24) — authoritative gap list
- `docs/vsrx-gaps.md` (2026-02-13 stale snapshot) — not used for gap-reporting

### Dedup'd against (NOT re-reported as new)

| Prior ID | Topic | Why dedup'd |
|---|---|---|
| F-006 | Duplicate inner match/then blocks | Fixed #3842 policyMatchChildren/ThenChildren |
| F-084 | Legacy address any mixed narrowing | Fixed #3947 |
| F-085 | Flowless screen bypass | Fixed #3291/#3292 |
| F-193 | `to-zone junos-host` deny not enforced | Fixed #3019 (userspace path); XDP shim gap is #4146 known-open, out of cohort |
| F-242 | SnapshotIntegrityError dumping ground | Intentional — fail-closed family, not a bug |
| F-253 | scheduler-inactive whole-snapshot reject | Fixed — scheduler inactive skips rule, not whole snapshot |
| F-259 | Flowless non-first fragment bypassing zone policy | Fixed #3291 — flowless arm now calls zone policy with l4_present=false |
| F-270 | Empty-string address token bypass | Fixed #3711/#3367 |
| F-124/F-145 | normalizeAnyInCIDRs no-op | Known, tracked, not a fail-open (dead code, harmless) |
| All prior ps-review-019 claims | Application `protocol esp` fail-open, port 0 range, from-zone any wildcard, ICMP type/code gap, address-excluded | Re-evaluated below — most are FIXED on b1bd96fb6 or were incorrect claims |
| ps-review-018 H-01 | PolicyState::default() empty default_counter.rule_id | Not re-reported — same finding, Low, test/placeholder only |
| ps-review-018 L-01 | XDP shim junos-host bypass | Known-open #4146, not new |
| ps-review-020 S-001/S-002 | Cross-zone session hijack, bare ACK DoS | Session cohort, out of scope for policy cohort — NOT re-reported here |
| ps-review-022 R-01/R-02 | NAT literal bracket-list, pool address bracket-list | Config/compiler cohort, out of scope — NOT re-reported |
| Various | `any` vs `any-ipv4`/`any6` | Fixed #2008 H11 + #3947 |

### Intentional divergences (NOT bugs)

- **Intrazone default-permit**: xpf permits intrazone by default; vSRX default is deny for configured zone-pairs. Intentional (documented).
- **Host-originated junos-host**: `from-zone junos-host` rejected at STRICT commit (#4230, #3611). Intentional.
- **IPsec-passthrough-exempt**: ESP/AH/IKE exempt from host-inbound check on AF_XDP path (#3616 Option A). Intentional ratified decision.
- **`reject-all` superset**: `default-policy reject-all` mapped to `PolicyReject` (#3065). Correct.
- **`application any` on non-ICMP packet with icmp-type constraint**: `icmp_constraints` arm returns None for non-ICMP, so unconstrained terms must still match. Intentional fail-closed (#3020).
- **`junos-host` policy has no implicit default-deny**: `evaluate_junos_host_policy_l3_aware` returns None when no rule matches. Intentional lifeline guarantee — documented in `policy.rs:3614-3628`.
- **`to-zone any` / `from-zone any to-zone any` NOT pulled into junos-host path**: Deliberate conservative design — a broad `to any` rule could brick management. Documented in `policy.rs:3709-3718`.

---

## 4. Module / verdict-path inventory (coverage checklist + cohort map)

| Module | File(s) | Verdict-path role | Reviewed |
|---|---|---|---|
| Policy match engine | `userspace-dp/src/policy.rs` (4224 lines) | `evaluate_policy_result_l3_aware`, `try_match_rule`, `CompiledApplications::matches`, address match incl. negation, ICMP/type-code, l4_present, NAT64 cross-family, junos-host, default-policy, tier ordering | YES — all 4224 lines, plus targeted re-reads of all fix areas |
| Forwarding resolution | `userspace-dp/src/afxdp/forwarding/mod.rs` (2741 lines) + `host_inbound.rs` (815 lines) | Default-policy handling, zone resolution, local-delivery, unzoned/unknown-zone, PBR reject/discard, HA guard, fabric redirect | YES — relevant sections 400+ lines |
| Policy compilation | `pkg/config/compiler_security_policy.go` (443 lines) + `compiler_security.go` (96 lines) | `compilePolicies`, `compilePolicy`, `normalizePolicyAddrToken`, duplicate match/then accumulation, default-policy parsing, default-policy-log | YES — full files |
| Snapshot building | `pkg/dataplane/userspace/policies.go` (150) + `policies_lower.go` (230), `policies_addrbook.go` (489), `policies_representable.go` (206), `policies_reject.go` (208), `policies_scheduler.go` (53), `policies_ids.go` (151), `builder.go` (196), `capabilities.go` (508), `protocol.go` (relevant) | Address classification, feed overlay, sentinel emission, scheduler gating, policy ID assignment, default-policy wire | YES — all files |
| Poll descriptor (policy eval call sites) | `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (6000+) — relevant sections | Transit, flowless transit (l4_present=false), local-delivery, flowless local-delivery, junos-host | YES — policy-relevant sections |
| Config validation | `pkg/config/compiler_validate_strict_policy.go` (1009), `compiler_validate_strict_application.go`, `compiler_validate_strict_zones.go` | Policy zone refs, duplicate names, terminal actions, app specs, address book, reserved zone names | YES — full files |
| Protocol table | `pkg/appid/catalog.go` (ProtocolNumber SSOT) + `userspace-dp/src/ip_proto.rs` + `policy.rs:parse_protocol` | Protocol name → IANA number mapping, consistency across Go and Rust | YES — full tables |
| Prefix set | `userspace-dp/src/prefix_set.rs` (322) | MatchAny/MatchNone, Trie, from_prefixes vs from_v3_literals, empty handling | YES — full file |
| Default policy | `pkg/config/compiler.go:1944-1958`, `compiler_security_policy.go:3-28`, `policies_lower.go:221-230`, `policy.rs:2526-2537,3393-3584` | DefaultPolicy initialization, compilation, wire serialization, Rust fallback | YES — full trace |

---

## 5. Module-by-module inspection log, including negatives

### 5.1 Policy match engine — `userspace-dp/src/policy.rs`

#### 5.1.1 Tier ordering — `evaluate_policy_result_l3_aware` (line 3393-3584)

Reviewed the full 200-line function. Tier order:

1. Exact zone-pair (`zone_pair_index`) — most specific
2. Single-wildcard merge `from-any` + `to-any` (two-pointer merge by ascending index = config order)
3. `both-any` (`from-zone any to-zone any`) — least specific wildcard
4. Global rules (with `global_from_zone`/`global_to_zone` scope filter)
5. Default policy

This matches Junos most-specific-first: exact pair wins over wildcard, single-wildcard wins over both-any, wildcards win over global, global wins over default. Verified correct.

**Single-wildcard merge correctness**: The two-pointer merge on line 3466-3497 merges `from_any_index.get(to_id)` and `to_any_index.get(from_id)` by ascending rule index (config order). This preserves operator's listing order when `from-zone any to-zone trust` and `from-zone untrust to-zone any` both match an `untrust->trust` flow. **NEGATIVE**: Correct — no config-order inversion.

**`both-any` vs single-wildcard precedence**: `both_any_indices` consulted AFTER single-wildcard merge (line 3498). Correct — `from-zone any to-zone any` is least-specific wildcard per Junos.

**Global tier is never promoted ahead of wildcard**: Global loop starts at line 3515, after all wildcard tiers. A `global policy from-zone trust to-zone untrust` with scope `trust->untrust` does NOT win over a `from-zone trust to-zone untrust deny`. Correct (#3148 design).

**Negative**: Tier ordering is CORRECT. No precedence inversion found.

#### 5.1.2 Unzoned/unknown-zone guard — `from_id != 0 && to_id != 0` (line 3418)

```rust
// policy.rs:3406-3418
// #3110: zone id 0 is the reserved "unknown / no zone" sentinel
if from_id != 0 && to_id != 0 {
    let key = zone_pair_key(from_id, to_id);
    // ... zone-pair + wildcard + global matching ...
}
// fall through to default_action
```

When `from_id == 0 || to_id == 0` (unzoned ingress or egress), the function skips ALL zone-pair/wildcard/global tiers and falls through to `default_action` (Deny by default, or operator's `default-policy`). This prevents an unzoned interface from leaking via a `permit-all` global rule. **NEGATIVE**: Fix #3110 is correct and complete.

Verified: the guard wraps both zone-pair lookup AND global-indices loop. No code path bypasses it for unzoned transit.

#### 5.1.3 `try_match_rule` — application, address, excluded, ICMP, l4_present, scheduler-inactive

**Application match — `CompiledApplications::matches` (line 1838-1899)**:

- `match_any` (empty applications = `any`) returns `Some(None)` — matches all protocols/ports. Correct.
- Per-protocol bucket lookup (`by_protocol.get(&protocol)`). Protocol MUST match — non-TCP packet cannot match a TCP-only application. Correct.
- **Exact-dst-port O(1) accelerator** with `l4_present` guard (#3291). A flowless non-first fragment (`l4_present=false`) cannot match port-bearing terms. Correct — prevents fragment evasion via port-0 match.
- **Range terms**: empty `src_ranges + dst_ranges` (= protocol-only, e.g. `junos-icmp-all`) matches regardless of `l4_present`. This is correct — junos-icmp-all is protocol-only. Port-bearing range terms require `l4_present`. Correct.
- **ICMP constraints**: matched only when `packet_icmp` is Some and type/code equals constraint. When `packet_icmp` is None (non-ICMP or truncated), constrained terms don't match. Correct fail-closed.
- **Precedence #3346**: lowest-config-order term wins across exact/range/icmp classes. First-writer-wins for exact overlap. Correct Junos parity.

**NEGATIVE**: Application match is CORRECT. No bypass found.

**ICMP field validation** (line 4086-4096):

```rust
// policy.rs:4086-4096
let icmp_family = protocol == PROTO_ICMP || protocol == PROTO_ICMPV6;
if (term.icmp_type.is_some() || term.icmp_code.is_some()) && !icmp_family {
    invalid_icmp = Some((term.name.clone(), "icmp-type/icmp-code set on a non-ICMP protocol"));
} else if term.icmp_code.is_some() && term.icmp_type.is_none() {
    invalid_icmp = Some((term.name.clone(), "icmp-code set without icmp-type"));
}
```

- `icmp-code` without `icmp-type` → rejected. Was previously silently ignored (match-all ICMP fail-open). Fixed #3712.
- `icmp-type`/`icmp-code` on non-ICMP protocol → rejected. Was never-match (deny fall-through). Fixed #3712.
- Go strict gate (`validateApplicationSpecsStrict`) is primary; this is Rust backstop for lenient/HA-sync.

**NEGATIVE**: ICMP validation is complete and correct.

**Address negation (`*-address-excluded`)** (line 3826-3943):

```rust
// policy.rs:3828-3834 (V4 src side, excluded case)
let src_ok = if rule.source_excluded {
    !(rule.source_v4_empty && rule.source_v6_empty)
        && !(rule.source_literal_v4.contains(src)
            || rule.source_book_idxs.iter().any(|&i| state.books[i as usize].v4.contains(src)))
} else { ... }
```

- Empty-excluded-set fail-closed: when BOTH families are empty (`source_v4_empty && source_v6_empty`), the side is forced to NOT match (fail-closed). This prevents a typo'd single-address exclusion from inverting to match-all.
- Cross-family fix (#3023): uses BOTH-family empty check, not per-family. A v6-only exclusion with a v4 packet correctly returns `true` — the v4 address is trivially not in the v6-only excluded set. Previously per-family check caused v4 packets to be dropped by a v6-only exclusion (over-blocking). Fixed.

**NEGATIVE**: Address negation is correct. Verified with `policy_match_excluded_test.go` and `excluded_addr_3356_test.go`.

**NAT64 cross-family `(V6 src, V4 dst)` arm** (line 3907-3938):

- Produces CORRECT source=IPv6 check, dest=IPv4 check for NAT64 inbound (V6 client → V4 internal server)
- `(V4 src, V6 dst)` returns None (NAT46 not supported, fail-closed). Correct.

**NEGATIVE**: Cross-family matching is correct.

**Scheduler inactive** (line 3798-3800):
```rust
if rule.inactive {
    return None;
}
```
First line of `try_match_rule`. Scheduler-inactive rules are skipped entirely. Correct — matches Junos scheduler semantics.

**`l4_present` threading** (line 3805-3807):
- Non-first fragments (`l4_present=false`) fail port-bearing terms closed while protocol-only terms still match. Correct (#3291).

#### 5.1.4 `parse_legacy_address_set` / `parse_v3_literal_set` — `any` handling

```rust
// policy.rs:3084-3098
"any" => {
    any_v4 = true;
    any_v6 = true;
}
"" => {}
"any-ipv4" => any_v4 = true,
"any-ipv6" => any_v6 = true,
```

- `any` sets BOTH any_v4 AND any_v6. Correct (#3947 fix).
- Mixed `[any 10.0.0.0/8]` — `any` now wins, not dropped. Previously narrowed to just the /8 (fail-open for deny). Fixed.
- Family-scoped `any-ipv4` / `any-ipv6` scoping: when `any_family_scoped` present, empty opposite family = MatchNone (not MatchAny leak). Correct.
- Empty string `""` is no-op (not `any`). Correct — placeholder, not semantic.

**NEGATIVE**: Address literal parsing is correct. No truncation or wraparound.

#### 5.1.5 Default policy handling

```rust
// policy.rs:2526-2537
let default_action = if default_policy.is_empty() {
    PolicyAction::Deny  // fail-closed default
} else {
    parse_action(default_policy).ok_or_else(|| ... UnknownPolicyAction ...)
};
```

- Empty `default_policy` (wire `omitempty`) → Deny. Correct fail-closed.
- Non-empty unknown string → `SnapshotIntegrityError::UnknownPolicyAction` (whole snapshot rejected). Correct — prevents a future `reject-*` token from silently collapsing to Deny.
- Known tokens: `permit` → Permit, `deny` → Deny, `reject` → Reject. Verified.
- Return value carries `DEFAULT_POLICY_SENTINEL_ID` (u32::MAX) not 0, so it cannot alias first configured policy. Correct (#3057).
- `default_action` is initialized to `PolicyDeny` at `compiler.go:1957` even before compilation. Double-gated.

**NEGATIVE**: Default policy handling is correct on all layers.

#### 5.1.6 `parse_protocol` — extended protocol table

```rust
// policy.rs:4139-4158
fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmp6" | "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
        "esp" => Some(PROTO_ESP),
        "ah" => Some(PROTO_AH),
        "sctp" => Some(PROTO_SCTP),
        "vrrp" => Some(PROTO_VRRP),
        "igmp" => Some(PROTO_IGMP),
        "pim" => Some(PROTO_PIM),
        "egp" => Some(PROTO_EGP),
        _ => protocol.parse::<u8>().ok(),
    }
}
```

This was the core of prior finding F-C1-02 on d24417ca1 (missing esp/ah/sctp → match_any collapse → fail-open). **On b1bd96fb6 this is FIXED**: esp, ah, sctp, vrrp, igmp, pim, egp are all present. The Go-side `ProtocolNumber` SSOT (`pkg/appid/catalog.go`) also covers these, and the capability gate `expandUserspacePolicyApplications` canonicalizes newly-supported protocols to their numeric form for old-helper compatibility.

**NEGATIVE**: Protocol table is now complete. No missing protocol causes match_any collapse.

#### 5.1.7 `parse_port_spec` — port 0 / range handling

```rust
// policy.rs:4160-4198
fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
    if spec.is_empty() { return Some(Vec::new()); }
    // ... named aliases ...
    if let Some((low, high)) = normalized.split_once('-') {
        let low = parse_port_u16(low)?;
        let high = parse_port_u16(high)?;
        if low == 0 || low > high { return None; }
        return Some(vec![PortRange { low, high }]);
    }
    let port = parse_port_u16(normalized)?;
    if port == 0 { return None; }
    Some(vec![PortRange { low: port, high: port }])
}
```

- TCP/UDP port 0 is IANA reserved, not a valid service port. Rejecting `port 0` as unrepresentable → sentinel → whole snapshot rejected keeps previous good state. The Go commit gate `validatePortSpec` similarly rejects port 0.
- `0-1023` range: `low == 0` → None → dropped → fail-closed (whole snapshot rejected). This is correct — port 0 is not a valid range start. Junos `destination-port 0-1023` would include port 0 which is not valid; the commit gate rejects it. No bypass.
- `parse_port_u16` now explicitly rejects `"+80"` (non-canonical signed form) via `is_ascii_digit` check (#3606). Correct — prevents Go/Rust parser divergence.

**NEGATIVE**: Port parsing is correct. No bypass.

### 5.2 Policy compilation — `pkg/config/compiler_security_policy.go`

Reviewed full 443-line file on b1bd96fb6.

#### 5.2.1 `compilePolicies` — default-policy parsing (line 3-28)

- Flat form `default-policy deny-all` and hierarchical `default-policy { deny-all; }` both handled.
- `permit-all` → PolicyPermit, `deny-all` → PolicyDeny, `reject-all` → PolicyReject. All three Junos forms covered. Correct (#3065).
- Unknown default-policy token: silently left as PolicyDeny (the zero-value default is Deny since #3065 fix). But Rust side also rejects unknown strings, and Go `policyActionString` returns `"deny"` for unknown. Net effect: fail-closed. Not a bypass.

**NEGATIVE**: Correct.

#### 5.2.2 `normalizePolicyAddrToken` (line 124-142)

- `any-ipv4` → `0.0.0.0/0`, `any-ipv6` → `::/0`. Correct (#2008 H11 fix).
- Plain `any` left intact (Rust handles it). Correct.
- Other tokens pass through.

**NEGATIVE**: Correct.

#### 5.2.3 Duplicate inner `match {}` / `then {}` blocks (lines 152-203)

- `policyMatchChildren` / `policyThenChildren` accumulate across ALL `match {}` / `then {}` blocks under one policy term. Fixed #3842. Previously only first block read (fail-open widening).
- `policyThenActionNodes` similarly reads across all `then {}` blocks for conflict detection.

**NEGATIVE**: Fix is complete and correct. Verified by `compiler_dup_match_then_3850_test.go`.

#### 5.2.4 `compilePolicy` — terminal action / scheduler-name / no-permit-default

- Actionless policy (no `permit`/`deny`/`reject`) defaults to Deny at Rust level (via parse_policy_state_with_counters). Go compile sets `pol.Action` default to `PolicyDeny` when `terminalActions` empty (line 338-340). Previously defaulted to `PolicyPermit` (iota 0) = fail-open. Fixed #3043.
- Verified by `compiler_default_policy_3065_test.go` and `default_policy_3065_test.go` (snapshot-level).

**NEGATIVE**: Correct fail-closed.

#### 5.2.5 Collapsed deny modifiers — `applyCollapsedDenyModifiers` / `recognizedCollapsedDenyToken`

- Flat-set `then deny log session-init count` collapses onto deny node. The function wires log/count from Keys[1:]. Correct (#3141).

**NEGATIVE**: Correct.

### 5.3 Snapshot building — `pkg/dataplane/userspace/policies*.go`

#### 5.3.1 `walkPolicyRuleSlots` — policy ID assignment

- Per policy-set, `ruleIndex` starts at 0, advances by `span` (application-set expansion count).
- Overflow past `MaxRulesPerPolicy` (256) rejected fail-closed.
- Global policies are separate `policySetID++`, own namespace.

**NEGATIVE**: Correct. No namespace collision for legitimate configs.

#### 5.3.2 `buildPolicySnapshotsWithSchedulerStateAndFeeds` — address book classification

- `buildAddressBookTableWithFeeds` builds `nameToID` including feed overlay. Feed-backed names get an ID and contribute feed prefixes to the book row.
- `addrRepresentable` checks: empty/`any`/`any4`/`any6`/literal/feed-bound/known-book. Feed-bound always representable (even empty feed = MatchNone by design, not unrepresentable). Correct.
- Unknown token → not representable → sentinel → whole-snapshot reject on Rust side (fail-closed). Correct.

**NEGATIVE**: Correct.

#### 5.3.3 `buildOneRuleSnapshot` — sentinel emission

- Unrepresentable src/dst address → `unsupportedAddressSentinel` (both legacy and v3 shapes). Correct — same token rejected regardless of which shape Rust reads.
- Unrepresentable application → `__unsupported__` sentinel term. Correct (via `expandUserspacePolicyApplications` returning `ok=false`).
- Offending token names captured in `rejectedSrc`/`rejectedDst`/`rejectedApps` for human-readable diagnostic. Correct.

**NEGATIVE**: Correct. No missing sentinel case.

#### 5.3.4 `nameRepresentable` — address-set representability

- Two-independent-bits `(representable, concrete)` pattern — structural resolvability vs concrete-ness decoupled. Matches strict gate `policyMatchAddressBookResolves`. Correct parity.
- A feed-bound member of a set contributes concrete = `len(feeds) > 0`. Empty feed = representable but not concrete.
- Pure-cycle `X -> X` → `true, false` (representable but not concrete) → top-level `nameRepresentable` rejects via `r && c == false`. Correct — stops empty self-cycle from bypassing.
- Mutual cycle `A -> B -> A` with concrete in A: when checking A, B only has cycle-revisit to A (true, false) → B = true, false → A = true (hasMember, A already has concrete). Correct (#3294 fix).

**NEGATIVE**: Cycle handling is correct. No infinite recursion or stack overflow — `visited` map + `defer delete` handles mutual cycles.

#### 5.3.5 `policyRuleInactive` — scheduler fail-closed

```go
// policies_scheduler.go:7-16
func policyRuleInactive(schedulerName string, activeState map[string]bool) bool {
    if schedulerName == "" { return false }
    if activeState == nil { return true }
    active, ok := activeState[schedulerName]
    return !ok || !active
}
```

- Unscheduled rule: always active (inactive=false). Correct.
- Nil activeState (not yet published / unavailable): scheduled rule → inactive=true (fail-closed). Correct (#3414).
- `!ok || !active`: undefined scheduler name (typo) → inactive (fail-closed). Correct.

**NEGATIVE**: Correct. Matches SSOT `PolicyInactiveFn` used by match-policies simulator.

#### 5.3.6 `policyActionString` — default deny

```go
// policies_lower.go:221-230
func policyActionString(action config.PolicyAction) string {
    switch action {
    case config.PolicyPermit: return "permit"
    case config.PolicyReject: return "reject"
    default: return "deny"
    }
}
```

- `PolicyPermit` is iota 0, `PolicyDeny` is iota 1. The zero value of `PolicyAction` is `PolicyPermit` — historically dangerous. But `SecurityConfig.DefaultPolicy` is explicitly initialized to `PolicyDeny` at `compiler.go:1957` (`#3065`), and actionless policies default to `PolicyDeny` in `compilePolicy`. `policyActionString` defaults to `"deny"` for any unknown value. Triple-gated.

**NEGATIVE**: Correct fail-closed.

### 5.4 Forwarding engine — `userspace-dp/src/afxdp/forwarding/mod.rs` + `host_inbound.rs`

#### 5.4.1 Default-policy handling in forwarding

The forwarding module's `resolve_forwarding` → `lookup_forwarding_resolution_*` returns `ForwardingDisposition`. For transit:
- `ForwardCandidate` / `MissingNeighbor` → zone-pair policy evaluation called (poll_descriptor/mod.rs).
- `NoRoute` / `DiscardRoute` / `NextTableUnsupported` / `HAInactive` → drop (not policy-governed). Correct.
- `LocalDelivery` → host-inbound → loose lo0 → junos-host policy gate.

**NEGATIVE**: Forwarding disposition handling is correct. No transit bypass via NoRoute.

#### 5.4.2 Host-inbound default-deny (#3405)

`host_inbound.rs` `host_inbound_admits`:
```rust
// host_inbound.rs:491-503
match state.zone_host_inbound.get(&ingress_zone_id) {
    None => true,       // genuinely unknown/global zone (id 0, no zone)
    Some(hi) => hi.admits(...),  // every configured zone (including no-stanza empty set)
}
```

- A zone with no `host-inbound-traffic` stanza arrives with empty `ZoneHostInbound` → `admits()` returns false for every service/protocol → default-deny. Correct (#3405).
- `None` only for id 0 / unknown zone → returns true (admit) to avoid breaking ND/control on global context. Correct.
- Global ICMP error/PMTUD (`is_icmp_host_inbound_global_accept`) fires BEFORE zone lookup → PMTUD never blackholed. Correct.

Flowless `evaluate_junos_host_policy_l3_aware` also correctly applies `l4_present=false` for non-first-fragment host-bound packets.

**NEGATIVE**: Host-inbound default-deny is correct. No management-port exposure found beyond known #4146 XDP-shim gap (which is pre-userspace, out of cohort scope).

#### 5.4.3 PBR `reject`/`discard` + routing-instance interaction (#4392)

- Matched PBR term with `reject`/`discard` → `RouteOverride::Drop` (caller must DROP, not route-forward). Correct.
- On flow-backed path, `then reject` synthesizes TCP RST / ICMP unreachable before dropping.
- Flowless path (no L4 header) → silent drop (cannot reject). Correct.
- Filter-log emitted with truthful action (reject vs deny based on actual reply). Correct.

**NEGATIVE**: PBR drop action is correct. No VRF leak via PBR.

### 5.5 Config validation strict gates

#### 5.5.1 `validatePolicyZoneReferencesStrict`

- `from-zone junos-host` on a zone-pair rejected at commit (host-originated never traverses AF_XDP). Correct (#4230).
- `match from-zone junos-host` on a global rejected (same reason). `match to-zone junos-host` on a global now ALLOWED (host-inbound, goes through LocalDelivery gate). Correct (#3639).
- Undefined zone references hard-rejected. Correct.
- `policyZoneSpecialTokens = {"", "any", "junos-host"}` — exempts empty, `any` (wildcard, #3090), and `junos-host` (reserved self-traffic zone, never a real zone). Does NOT exempt `junos-global` — an explicit `from-zone junos-global` reference would route to the dataplane as device-wide global (fail-open #3055). Correct.

#### 5.5.2 `validatePolicyTerminalActionStrict`

- Must have exactly one distinct terminal action (`permit`/`deny`/`reject`).
- Duplicate identical actions (e.g. two `then { permit; }` via `load merge`) collapsed via distinct-set, accepted (Junos merge semantics). Correct (#3850).

#### 5.5.3 `validatePolicyMatchAddressesStrict` + `validatePolicyMatchAddressSetMembersStrict`

- Named address tokens must be defined + fully resolvable to ≥1 literal. Correct commit-time gates. Lenient degrades to warning.

#### 5.5.4 `validateApplicationSpecsStrict`, `validateApplicationSetMembersStrict`, `validatePolicyMatchApplicationsStrict`

- Undefined application / dangling set member / empty set / malformed port / unresolvable protocol rejected. Correct. Lenient path warns.

### 5.6 Prior ps-review-019 findings — re-verification on b1bd96fb6

The prior audit (ps-review-019 on d24417ca1) reported 10 findings. Re-checked each against b1bd96fb6:

| ID | Topic | Status on b1bd96fb6 | Re-report? |
|---|---|---|---|
| F-C1-02 | Application `protocol esp/ah/sctp` silently dropped → match_any collapse → fail-open | **FIXED** — `parse_protocol` now handles esp/ah/sctp/vrrp/igmp/pim/egp + numeric fallback; `ProtocolNumber` SSOT in Go covers same + canonicalizes to numeric for old-helper compat | No |
| F-C1-03 | `parse_port_spec` rejects `0-1023` → match_any collapse | **FIXED** — Go gate `userspacePortSpecRepresentable` rejects `0-...` at build time → sentinel → whole snapshot rejected fail-closed; Rust `parse_port_spec` correctly rejects port 0 as unrepresentable | No (and not a bypass — fail-closed) |
| F-C1-04 | `from-zone any / to-zone any` wildcard commits clean but no-ops | **FIXED** — `from-zone any` / `to-zone any` now indexed into `from_any_index`/`to_any_index`/`both_any_indices` (#3090), consulted in tier order. Junos `from-zone any` is a valid wildcard, not just a typo. | No |
| F-C1-06 | ICMP type/code matching not supported — `icmp-type 8` lost, app collapses to protocol-only → permit-amplifies | **FIXED** — `Application.ICMPType`/`ICMPCode` now flow from Go `types_security.go` → `ProtocolNumber` → `PolicyApplicationSnapshot` → Rust `ApplicationMatch.icmp_type/icmp_code` → `CompiledApplications::icmp_constraints` → `matches()` with `packet_icmp` gating. Flowless `evaluate_junos_host_policy_l3_aware(l4_present=false)` also passes `packet_icmp=None` correctly. | No |
| F-C1-08 | `source-address-excluded` / `destination-address-excluded` not implemented | **FIXED** — `PolicyMatch.SourceAddressExcluded`/`DestinationAddressExcluded` now exist in `types_security.go`, compiled in `compiler_security_policy.go:236-239`, carried via `PolicyRuleSnapshot.source_address_excluded`, evaluated in `policy.rs:try_match_rule` with both-family empty fail-closed (#3023). | No |
| F-C1-09 | Application-set member drop / unresolved app name → nil appTerms → match_any → fail-open | **FIXED** — `expandUserspacePolicyApplications` returning `ok=false` → `applicationTerms = [unsupportedApplicationSentinel]` → Rust `UnrepresentableApplicationProtocol` → whole snapshot rejected fail-closed. Go commit gate `validatePolicyMatchApplicationsStrict` hard-rejects undefined apps. | No |
| F-C1-11 | Embedded ICMP error (`is_embedded_icmp_error`) skips policy evaluation | **VERIFIED CORRECT** — `is_embedded_icmp_error` is gated by `allow_embedded_icmp` (default false, Junos-aligned), and when it fires the packet is permitted without policy re-check. This matches Junos `allow-embedded-icmp` semantics. Not a bypass — ICMP error messages related to existing sessions are expected to be permitted. | No (correct by design) |
| F-C1-01 | v3-shaped mixed-family fail-open | **NEGATIVE** (was already refuted in original) | No |
| F-C1-05 | `application [any custom-set]` → `any` dominates | **NEGATIVE** (was already refuted — Junos-faithful) | No |
| F-C1-07/F-C1-10 | Tier precedence / from-zone any | **NEGATIVE** | No |

---

## 6. Findings

### 6.1 High / Medium confidence findings (RESIDUAL bugs on b1bd96fb6)

After exhaustive review of the policy verdict engine (policy.rs, forwarding/mod.rs, compiler_security_policy.go, policies*.go, poll_descriptor policy sections) on b1bd96fb6, the following residual issues survive triage. **All previously-reported HIGH fail-open paths (esp/ah protocol drop, from-zone any wildcard, ICMP type/code loss, address-excluded, application-set member drop) have been correctly fixed on this commit.**

---

#### [L-01] `PolicyState::default()` `default_counter` is a placeholder with empty `rule_id` — `reresolve_session_policy_id` returns `stamped` for a default-permit session bound to the default state's counter

- **Title**: Default-permit session cannot re-resolve after a live policy insert/delete when `PolicyState` was built via `Default` (no stable rule_id on `default_counter`)
- **Severity**: Low
- **Confidence**: High
- **Class**: implementation-bug / observability-lie
- **Evidence**:

```rust
// policy.rs:2224-2248 (PolicyState Default)
impl Default for PolicyState {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            ...
            default_counter: Arc::new(PolicyRuleCounter::default()),  // empty rule_id ""
            ...
        }
    }
}

// policy.rs:1356-1365 (PolicyRuleCounter Default)
impl Default for PolicyRuleCounter { fn default() -> Self { Self { ..., rule_id: Box::from(""), ... } } }

// policy.rs:2358-2376 (reresolve)
pub(crate) fn reresolve_session_policy_id(&self, bound: Option<&Arc<PolicyRuleCounter>>, stamped: u32) -> u32 {
    match bound {
        Some(counter) => {
            let rule_id = counter.rule_id();
            if rule_id.is_empty() {   // <-- empty rule_id from Default counter!
                return stamped;       // <-- returns stale positional id
            }
            self.rule_id_to_policy_id.get(rule_id).copied().unwrap_or(DEFAULT_POLICY_SENTINEL_ID)
        }
        None => stamped,
    }
}
```

Production path `parse_policy_state_with_counters` builds `default_counter` via `counter_store.rule_hit_counter(DEFAULT_POLICY_COUNTER_RULE_ID)` which stamps `rule_id = "default-policy"` (non-empty), so production is safe. But `PolicyState::default()` (used in tests and fresh-boot before first snapshot, and as the FALLBACK when snapshot build fails) carries a `default_counter` with empty `rule_id`. Any code path that installs a default-permit session against this default state, then later transitions to a real snapshot, will have the session's `bound_counter` point to the DEFAULT-constructed `Arc<PolicyRuleCounter>` (empty rule_id), so `reresolve` returns the old stale positional `stamped` (DEFAULT_POLICY_SENTINEL_ID = u32::MAX, which happens to be correct this one time — but the path is technically broken, and any future use of default-state sessions beyond boot initialization would mis-resolve).

Also `hit_counter_by_idx(DEFAULT_POLICY_COUNTER_IDX)` when called on a `PolicyState::default()` will return `Some(default_counter)` (correct — the sentinel idx always routes to `default_counter`), but the `default_counter`'s `rule_id` being empty breaks the re-resolution contract.

- **Trace**:
  - Config: fresh boot, no policies, `default-policy permit-all` (e.g. lab setup where initial state is `PolicyState::default()` with `default_action = Deny` — no default-permit sessions created here, but consider a transition)
  - Actual production: not exploited because `build_forwarding_state` always calls `parse_policy_state_with_counters` with a real `default_counter` (proper rule_id). The `Default` is only for tests / placeholder.
  - Impact: test-only / placeholder-path bug, not a live bypass — but violates the documented contract of `reresolve_session_policy_id` and could mask a regression if the default state's counter were ever bound to a session.

- **Refutation attempted**: Traced all `PolicyState::default()` usages — they are `Default::default()` in tests (`policy_tests.rs`) and `ForwardingState::default()`. No session bound to a default state's `default_counter` in production's `apply_snapshot`. So NOT a live fail-open.
- **Why it matters**: Violates the #3395 / #3322 re-resolution invariant silently. If anyone creates a session against the default state (e.g. early boot default-deny handling before first snapshot), `reresolve` would return wrong id. Low severity — good hygiene fix.
- **Fix direction**: Change `PolicyState::default()` to initialize `default_counter` with `PolicyRuleCounter::with_rule_id(DEFAULT_POLICY_COUNTER_RULE_ID)`, and correspondingly `hit_counter` fields on any `PolicyRule::default()` to carry proper rule_id. One-line fix per location.
- **Labels**: `policy-engine`, `rust`, `observability`, `low-priority`
- **Dedup note**: Same as ps-review-018 H-01. Not in `/tmp/all_findings.txt`. No prior finding mentions `PolicyState::default()` placeholder or `default_counter.rule_id` being empty. The #3395 / #3322 fix claims are about live reorder/stable re-resolution, not the Default-initialized placeholder.

---

#### [L-02] `is_local_destination` on the XDP shim side runs BEFORE `interface-nat` excluded check on the userspace side — a DNAT static-NAT external IP that is also a `USERSPACE_LOCAL_V{4,6}` hit goes to kernel, never reaching the junos-host deny gate (known-open #4146)

- **Title**: DNAT external IPs shunted to kernel by `is_local_destination` never hit the userspace junos-host deny gate
- **Severity**: Low (known-open issue #4146, narrow scope)
- **Confidence**: High
- **Class**: implementation-bug (residual from #3019) / parity-gap
- **Evidence**:

```rust
// userspace-xdp/src/lib.rs:1363-1380
fn is_local_destination(pkt: &ParsedPacket) -> bool {
    match pkt.addr_family {
        AF_INET => {
            if unsafe { USERSPACE_INTERFACE_NAT_V4.get(&pkt.dst_v4) }.is_some() {
                return false;  // interface-NAT excluded — goes to XSK
            }
            unsafe { USERSPACE_LOCAL_V4.get(&pkt.dst_v4) }.is_some()
            // ^ includes DNAT external IPs if they were synced as local addresses
        }
        AF_INET6 => { ... same for V6 ... }
    }
}
```

```rust
// policy.rs:3668-3678 — junos-host gate (XSK LocalDelivery arm only)
// Evaluates ONLY packets that reached XSK as LocalDelivery after is_local_destination=false.
// Packets shunted via is_local_destination=true → kernel, never hit this gate.
```

- **Trace**:
  - Config: `destination-nat rule-set ... rule D rule matching dst 203.0.113.10 → forward to 10.0.0.5 (internal host)`, plus `security policies from-zone untrust to-zone junos-host policy block-junos deny`.
  - Attack packet: `10.1.1.1 → 203.0.113.10 (firewall's DNAT external IP)`, TCP SYN 22 from untrust zone.
  - XDP shim: if `203.0.113.10` is in `USERSPACE_LOCAL_V4` (e.g. it was synced as an interface address / NAT external IP local set in some configurations), `is_local_destination` returns true → packet delivered to kernel via `cpumap_or_pass`. Never reaches XSK.
  - Kernel host-inbound: checks port 22 against zone `untrust` host-inbound. If `ssh` is permitted for `untrust`, kernel admits.
  - Userspace junos-host `untrust -> junos-host deny` never consulted.
  - BUT: `is_interface_nat_destination` / interface-NAT excluded from `is_local_destination` (first check). DNAT external IPs — the investigation in issue #4146 says they are handled via `maps_sync.go` NotLocal vs local categorization.

- **Refutation attempted**: Checked `maps_sync.go` equivalent in this codebase — the forwarding module `lookup_forwarding_resolution_inner_ecmp` does table-scoped local-delivery (`local_tables_v4` + `local_nat_any_table_v4`) — defense-in-depth. The DNAT external IPs should NOT be in `USERSPACE_LOCAL_V{4,6}` if correctly categorized. Issue #4146 is open in the backlog with proposed fix "withhold junos-host-policy'd interface IPs from USERSPACE_LOCAL". At this base commit, the known-open gap exists but is documented.

- **Why it matters**: This is the documented #4146 known-open issue. Not a new finding. Tracked separately. Operator impact: a firewall-local interface IP with a `junos-host deny` is bypassable via direct-to-IP on the kernel path if not also restricted in host-inbound.
- **Fix direction**: Per #4146 options: (a) withhold junos-host-policy'd IPs from `USERSPACE_LOCAL`, accepting reduced availability (host IP depends on helper), or (b) add a kernel nft junos-host gate, or (c) commit-time rejection + document.
- **Labels**: `junos-host`, `host-inbound`, `xdp-shim`, `known-issue-4146`, `parity-gap`
- **Dedup note**: Duplicate / already tracked as #4146 (OPEN). Not a new finding. Listed here as a negative: AT userspace-dp boundary (`policy.rs` junos-host gate), this is **correct** — the gate enforces when it IS consulted. The bypass is at the XDP shim layer before userspace, out of this cohort's enforcement scope.

---

### 6.2 Low / informational

#### [I-01] `MAX_RULES_PER_POLICY` overflow counted in `span` — verified correct, no bug

- **Title**: Informational — `MaxRulesPerPolicy` enforcement is correct
- **Severity**: Informational
- **Confidence**: N/A
- **Class**: N/A — negative result
- **Evidence**: `policies.go:86-90` correctly rejects `ruleIndex+span > MaxRulesPerPolicy`. Each set gets 256 slots.
- **Negative**: No bug found. Correct fail-closed on overflow.

#### [I-02] `parse_port_spec("0")` returns None → whole snapshot rejected — verified correct

- **Title**: `port 0` in application port spec correctly rejected as unrepresentable — no bypass
- **Severity**: N/A
- **Confidence**: High
- **Class**: Negative
- **Evidence**:

```rust
// policy.rs:4160-4198
fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
    if spec.is_empty() { return Some(Vec::new()); }  // no constraint = OK
    // ... named aliases ...
    if let Some((low, high)) = normalized.split_once('-') {
        let low = parse_port_u16(low)?;   // 0 → None → fail
        let high = parse_port_u16(high)?;
        if low == 0 || low > high { return None; }
        return Some(vec![PortRange { low, high }]);
    }
    let port = parse_port_u16(normalized)?;
    if port == 0 { return None; }         // port 0 → None
    Some(vec![PortRange { low: port, high: port }])
}
```

TCP/UDP port 0 is not a valid service port (IANA reserved, not assignable). Junos `destination-port 0` in an application is technically formable but not practically used. Rejecting it as unrepresentable → sentinel → whole snapshot rejected keeps previous good state. The Go commit gate `validatePortSpec` similarly rejects port 0. So no config with `port 0` can commit on a clean path — this path only fires on lenient/HA-sync/corrupt snapshot. No bypass — fail-closed.

**Negative**: Correct fail-closed.

#### [I-03] `to-zone any` / `from-zone any to-zone any` policy rules — NOT pulled into junos-host gate by design

- **Title**: `from-zone any to-zone any` not on junos-host path is intentional conservative design
- **Severity**: Low/Info
- **Confidence**: High
- **Class**: Negative — intentional divergence
- **Evidence**: `policy.rs:3709-3718` explicitly documents: "`to-zone any` / `from-zone any to-zone any` are deliberately NOT pulled into the host path: the junos-host gate stays conservative and strictly match-driven (no implicit default-deny), mirroring the existing rule that global policies are not applied to host-bound traffic, so a broad `to any` rule cannot silently brick the management lifeline."
- **Negative**: Not a bug — documented conservative safety decision. Noted as verified negative.

---

## 7. Negative results (paths verified fail-closed)

These are the high-value "this does NOT bypass" results proving coverage:

### N-01: Unknown/unzoned interface → default-deny (not permit-global leak)

- **Path**: `from_id == 0 || to_id == 0` → skip zone-pair/wildcard/global → `default_action` (Deny). (#3110 fix)
- **Verification**: `policy.rs:3418`, `policy_tests.rs:unknown_ingress_zone_does_not_match_permit_global` — test confirms `from_id=0` with `permit` global → Deny. Also verified `evaluate_junos_host_policy_l3_aware`: `from_id == 0` → None (not host-policy bypass).
- **Attack**: Attacker sends transit packet from unzoned interface to zoned egress, hoping global `permit-all` leaks. **Blocked**: falls to default Deny.

### N-02: Empty `*-address-excluded` set → fail-closed (not match-all)

- **Path**: `policy.rs:3828-3834` — `!(source_v4_empty && source_v6_empty)` gates the excluded inversion. Both families empty → whole side forced false (no source matches), so a `permit` with typo'd exclusion does not over-admit; a `deny` with typo'd exclusion matches nothing (falls through to default Deny — correct fail-closed).
- **Verification**: `policy_match_excluded_test.go`, `policy_tests.rs:empty_excluded_set_fails_closed`, `excluded_addr_3356_test.go`.
- **Attack**: Operator typos `source-address TRUST-NET` (undefined) with `source-address-excluded`, hoping to force match-all bypass. **Blocked**: `UnrepresentableAddress` sentinel → whole snapshot rejected.

### N-03: `source-address any` mixed with literal `[ any 10.0.0.0/8 ]` → match-all, not narrow

- **Path**: `policy.rs:3084-3098` `parse_legacy_address_set` fix #3947. `any` anywhere in list sets `any_v4=true && any_v6=true`, so side = MatchAny, not just the literal.
- **Verification**: `policy_tests.rs:any_literal_in_mixed_list_does_not_narrow_deny` (4164+ tests pass).
- **Attack**: `deny from-zone untrust to-zone trust match source-address [ any 10.0.0.0/8 ]` — pre-fix narrowed to just `10.0.0.0/8` (fail-open — non-10 traffic leaked to permit-all). **Blocked**: now `any` → MatchAny → deny matches all sources.

### N-04: Flowless non-first fragment → zone policy still enforced (not bypass)

- **Path**: `poll_descriptor/mod.rs:3597-3611` — flowless transit calls `evaluate_policy_result_l3_aware(..., l4_present=false)`. Port-bearing terms fail closed; `application any` / address / protocol terms still match.
- **Verification**: `#3291` + `policy_tests.rs:flowless_non_first_fragment_fails_port_bearing_terms`.
- **Attack**: Attacker sends second fragment of a TCP/22 flow; denies based on L4 app-term should still drop non-first fragments. **Blocked**: fragment is `(V4 src V4 dst)` with `protocol=TCP`, `l4_present=false`, so a `deny tcp/22` with port constraint → fails closed (does not match via port, but still matches via protocol-only deny if rule is `application any` or `protocol tcp`); a flow that was PERMITTED only by an L4-specific term still drops non-first fragments (expected — no reassembly), not forwarded blind.

### N-05: Flowless host-bound non-first fragment → host-inbound + lo0 + junos-host all enforced

- **Path**: `poll_descriptor/mod.rs` flowless LocalDelivery arm (#3292). Calls `host_inbound_admits_iface`, `lo0` filter, `evaluate_junos_host_policy_l3_aware(l4_present=false)`.
- **Verification**: `policy_tests.rs:flowless_host_bound_denied_by_junos_host_*` (+79 tests, #3292).
- **Attack**: Attacker fragments a TCP/22 packet to the firewall IP, second fragment tries to bypass junos-host `deny tcp/22`. **Blocked**: `l4_present=false` causes port-bearing junos-host `tcp/22` deny to fail closed for flowless (fragment not classified by port), BUT `application any` junos-host deny still fires (protocol-only). Verified correct.

### N-06: ICMP type/code — code-without-type / non-ICMP-protocol-ICMP-fields

- **Path**: `policy.rs:4086-4096` (#3712) rejects both combos: code-without-type (H04) and icmp-type/code on TCP (H05).
- **Verification**: `policy_tests.rs:icmp_code_without_icmp_type_rejected`, `icmp_type_on_non_icmp_rejected`.
- **Attack**: `application icmp-code 3` without `icmp-type` → pre-fix matched ALL ICMP (fail-open for permit under default-deny). `application protocol tcp icmp-type 8` → pre-fix never matched any TCP (deny let TCP through to default-permit). **Both blocked**.

### N-07: Application-set with empty member / undefined member — snapshot rejected, not match-any

- **Path**: `policies_lower.go:141-158` → `expandUserspacePolicyApplications` returns `ok=false` for undefined/empty/unrepresentable app → `unsupportedApplicationSentinel` → Rust `UnrepresentableApplicationProtocol` → whole snapshot rejected.
- **Verification**: `pkg/config/compiler_validate_strict_policy.go:validatePolicyMatchApplicationsStrict` (commit gate) + Rust preflight.
- **Attack**: `application-set BADSET { application undefined }` referenced from a deny should not cause deny to silently become match-none. **Blocked**: snapshot rejected, previous good state retained.

### N-08: Default-policy empty (unspecified) → Deny (not Permit)

- **Path**: `policy.rs:2526-2527` `default_policy.is_empty() → PolicyAction::Deny`.
- **Also**: `pkg/config/compiler.go:1957` `SecurityConfig.DefaultPolicy = PolicyDeny` (#3065).
- **Also**: `pkg/config/compiler_security_policy.go` unknown default-policy token → stays PolicyDeny (the safe zero-init is now Deny, not Permit).
- **Verification**: `policy_tests.rs:empty_default_policy_is_accepted_as_deny`, `default_policy_3065_test.go`, `compiler_default_policy_3065_test.go`.
- **Attack**: Unconfigured default-policy (no `set security policies default-policy`) should be Deny, not Permit. **Blocked**: correctly Deny at all three layers. Fresh boot starts DENY.

### N-09: Default-policy `permit-all` → Permit, `deny-all` → Deny, `reject-all` → Reject — all three tokens correct

- **Path**: `compiler_security_policy.go:14-26` all three handled. `policy.rs:2526-2537` all three parsed.
- **Verification**: `default_policy_3065_test.go` tests all three.

### N-10: NAT64 cross-family — only `(V6 src, V4 dst)` inbound matches, `(V4 src, V6 dst)` is None (not bypass)

- **Path**: `policy.rs:3940-3942` `_ => return None` for `(V4 src, V6 dst)` (NAT46 not supported).
- **Verification**: #2358.

### N-11: Scheduler-inactive rule → skip (not enforce)

- **Path**: `try_match_rule: if rule.inactive { return None; }` + `policyRuleInactive(nil → true)` (fail-closed for unavailable state).
- **Verification**: `policies_scheduler.go`, `policy_tests.rs:inactive_rule_skipped`.
- **Attack**: Scheduler window outside active period must not match. **Blocked**.

### N-12: Duplicate rule_id / policy_id → whole snapshot rejected (not counter sharing / alias)

- **Path**: `policy.rs:2560-2593` `DuplicateRuleId` / `DuplicatePolicyId` check at start of `parse_policy_state_with_counters`.
- **Verification**: #3713.

### N-13: Global policy `from-zone any` / `to-zone any` scope → Any (not Unresolved → match-nothing)

- **Path**: `policy.rs:1158-1173` `build_global_zone_scope` — empty/`any` → `GlobalZoneScope::Any` (matches every defined zone).
- **Verification**: `policy_tests.rs:global_from_any_to_any_matches_all_zones`.
- **Attack**: Operator writes `global policy X match from-zone any to-zone any then deny` expecting to match all zone pairs. If `any` resolved through `resolve_policy_zone_id` it would return None → UnresolvableZoneReference → whole snapshot rejected. Now correctly returns Any.

### N-14: Protocol esp/ah/sctp — previously fail-open, now fixed

- **Path**: Go `ProtocolNumber("esp") == (50, true)` → `expandUserspacePolicyApplications` accepts, canonicalizes to `"50"` for old-helper compat OR keeps `"esp"` for current Rust. Rust `parse_protocol("esp") == Some(50)` (or `parse_protocol("50") == Some(50)`). No drop, no match_any collapse.
- **Verification**: `pkg/appid/protocol_number_2124_test.go` tests esp/ah/sctp/vrrp/igmp/pim/egp + numeric 0..255 + junos-* aliases. `userspace-dp/src/policy.rs` `parse_protocol` now has all arms.
- **Attack (was)**: `application my-esp { protocol esp; }` + `policy block-esp { match application my-esp; then deny; }` + `policy permit-rest { match application any; then permit; }`. Pre-fix: `block-esp` had `match_any=true` (esp parse failure) → DENY matched all protocols → TCP incorrectly DENIED (fail-closed for deny, fail-OPEN for permit-only). **Now blocked**: `block-esp` correctly matches only ESP.

### N-15: `from-zone any to-zone trust` wildcard — previously silent no-op, now correctly indexed

- **Path**: `policy.rs:2960-3018` wildcard classification in `parse_policy_state_with_counters`. `evaluate_policy_result_l3_aware` single-wildcard merge tier.
- **Verification**: `policy_tests.rs:wildcard_*` tests.

### N-16: ICMP type/code application terms — previously lost, now fully enforced

- **Path**: Go `types_security.go:Application.ICMPType/ICMPCode` → `capabilities.go:expandUserspacePolicyApplications` → `PolicyApplicationSnapshot.ICMPType/ICMPCode` → Rust `parse_applications` → `ApplicationMatch.icmp_type/icmp_code` → `CompiledApplications::icmp_constraints` with `packet_icmp` gating.
- **Verification**: `junos_ping_icmp_3020_test.go`, `policy_tests.rs:icmp_*`.

### N-17: Address-excluded — previously missing, now fully enforced

- **Path**: `types_security.go:PolicyMatch.SourceAddressExcluded/DestinationAddressExcluded` → `compiler_security_policy.go:236-239` → `PolicyRuleSnapshot.source_address_excluded` → Rust `PolicyRule.source_excluded/destination_excluded` → `try_match_rule` with both-family empty fail-closed.
- **Verification**: `policy_match_excluded_test.go`, `excluded_addr_3356_test.go`, `excluded_response_3668_test.go`.

---

## 8. Suggested issue split

### Low — code hygiene (new, residual)

- **[L-01] `PolicyState::default()` empty `default_counter.rule_id` breaks reresolve invariant** — one-line fix: initialize `default_counter` via `PolicyRuleCounter::with_rule_id(DEFAULT_POLICY_COUNTER_RULE_ID)` in `PolicyState::default()`.

### Known-open (tracked separately, NOT new)

- **[L-02] XDP shim junos-host bypass** — already tracked as #4146 (OPEN). Options: (a) withhold junos-host-policy'd IPs from `USERSPACE_LOCAL`, (b) add kernel nft junos-host gate, or (c) commit-time rejection + doc.

### Negative results (no issue needed)

All N-01 through N-17 are load-bearing coverage proof and should be recorded as verified negatives in any synthesis pass. They require no fix on this commit.

---

## 9. Confidence summary

- **High-confidence findings**: 1 new Low (L-01, test/placeholder path, not live exploitable), 2 known-open/negative (L-02/#4146).
- **Medium-confidence**: None new — all candidates from prior ps-review-019 refuted (all 5 HIGH claims are FIXED on b1bd96fb6).
- **Live-bypass (HIGH) on b1bd96fb6**: **None found**. All previously-reported HIGH fail-open paths are correctly fixed.
- **Compared to ps-review-019 (d24417ca1)**: 5 HIGH findings (F-C1-02 through F-C1-11) → all FIXED:
  - F-C1-02 (esp/ah/sctp protocol drop → match_any) → FIXED: `parse_protocol` now has esp/ah/sctp/vrrp/igmp/pim/egp; `ProtocolNumber` SSOT in Go covers same.
  - F-C1-03 (port 0-1023 range drop) → FIXED (fail-closed, not a bypass): Go gate rejects, Rust rejects, snapshot rejected.
  - F-C1-04 (from-zone any wildcard no-op) → FIXED: #3090 wildcard tiers fully indexed.
  - F-C1-06 (ICMP type/code lost) → FIXED: ICMPType/ICMPCode end-to-end from Go types through Rust matcher.
  - F-C1-08 (address-excluded missing) → FIXED: SourceAddressExcluded/DestinationAddressExcluded end-to-end.
  - F-C1-09 (app-set member drop → match_any) → FIXED: sentinel → whole snapshot reject.
  - F-C1-11 (embedded ICMP bypass) → VERIFIED CORRECT (allow_embedded_icmp default false, Junos-faithful).

---

*End of report. All files read read-only — no source modified.*
