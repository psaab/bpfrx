# Codex Review 122: Firewall Core Quota Campaign

Date: 2026-07-01
Checkout: `/home/ps/git/codex-bpfrx`
Base commit: `bd2443c5ea3c564d6e0bbb308df7129b9d535ac6`
Command sync: `git pull --rebase` returned up to date.
Focus: vSRX-style core firewall behavior, especially zone/global policies, host-inbound, application matching, deny/allow correctness, structured policy introspection, and test coverage.

## Duplicate Suppression Read

I read the prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` reports plus the repo issue/backlog markdown. I intentionally suppressed these already-covered areas:

- Intrazone default-permit runtime/simulator/counter drift from `codex-review-121.md`.
- Host-originated junos-host policy enforcement, generated reply VLAN/host-inbound issues, output-filter reject divergence, unknown/global host-inbound gaps, host-inbound counters/logs, and AppID overlap/performance/HA issues from `codex-review-001.md`.
- Ident-reset AF_XDP drop and IPsec host-inbound bypass from `codex-review-002.md`.
- Session GC flag races, static NAT overwrite, signed port validation split, and dynamic feed slash/empty bypass from agy reports.
- Closed repo issues/PRs around VLAN host-inbound logical ifindex, conntrack GC race, flowless LocalDelivery/transit, lo0 nft modifiers, chain priorities, zone-pair include-peer, default-policy-log, SYN-flood timeout, nft counter declarations, syslog leak, generated app collision, zone-local display, screen-stat errors, duplicate-block AST bypass, duplicate policy names, scheduled policies failing closed in match-policies, unresolvable zones failing closed, snapshot/filter integrity, and NAT port-range expansion.

## Module Checklist

I inspected these modules/features. Negative results are included where I did not find a fresh non-duplicate issue.

1. AppID catalog and session-name runtime (`pkg/appid/runtime.go`, `pkg/appid/catalog.go`, tests and README).
2. Strict compiler AppID reference walker (`pkg/config/compiler_validate_strict.go`).
3. Userspace dataplane AppID catalog build path (`pkg/dataplane/userspace/flow.go`).
4. REST security policy inventory (`pkg/api/security.go`, `pkg/api/types.go`).
5. REST match-policies diagnostic API (`pkg/api/security.go`, `pkg/api/types.go`).
6. gRPC policy inventory and match-policies surfaces (`pkg/grpcapi/server_show_zones.go`, `pkg/grpcapi/server_cluster.go`, `proto/xpf/v1/xpf.proto`).
7. CLI `show security match-policies` surface (`pkg/cli/cli_show_security.go`).
8. Policy matcher core (`pkg/policymatch/policymatch.go`).
9. Policy compiler match-leaf validation (`pkg/config/compiler_policy_match.go`, `pkg/config/compiler_security.go`, schema tests).
10. Userspace policy snapshot builder (`pkg/dataplane/userspace/builder.go`, `userspace-dp/src/protocol/snapshot.rs`).
11. Rust userspace host-inbound classifier/runtime (`userspace-dp/src/afxdp/forwarding/host_inbound.rs`).
12. Protocol naming/display path (`pkg/appid/catalog.go`).
13. Structured policy tests and coverage (`pkg/api/*3331*`, `pkg/api/*3336*`, `pkg/appid/runtime_test.go`).
14. Reject/deny/local-delivery diagnostic wording paths.

Negative results:

- The Rust host-inbound classifier has a strong recognized-token table and parity test. I did not find a fresh enforcement bug beyond older unknown/global-zone issues already reported.
- `pkg/policymatch.Query` carries source port and ICMP type/code; I did not find a new core match omission there.
- The compiler unsupported match-leaf guard now has tail/unknown-leaf tests; I did not re-report that closed class.
- Host-inbound enforcement appears default-deny for configured zones and explicit for `all`; the fresh issues below are diagnostic/API completeness, not a discovered allow/deny data-path bypass.

## High Confidence Findings

### H01. REST policy inventory silently omits `policy_id` for the first runtime policy

Severity: Medium
Confidence: High
Labels: `bug`, `api`, `firewall`, `observability`

Evidence:

`pkg/api/types.go:164-180`

```go
	// PolicyID is the runtime policy identifier assigned by the compiler and
	// surfaced in RT_FLOW session logs.  It is stable until the policy order
	// changes and lets API consumers join policy inventory with runtime session
	// telemetry.  PolicyID is omitted when 0 (the first rule) or when the row is a
	// synthetic default policy.
	PolicyID uint32 `json:"policy_id,omitempty"`

	// RuleID is the 1-based rule number inside the containing scope.  It mirrors
	// Junos-style rule ordinals and is omitted for synthetic default policies.
	RuleID uint32 `json:"rule_id,omitempty"`
```

`pkg/api/security.go:164-173`

```go
			out = append(out, PolicyInfo{
				FromZone:   zpp.FromZone,
				ToZone:     zpp.ToZone,
				Name:       pol.Name,
				Action:     strings.ToUpper(pol.Action),
				PolicyID:   config.RuntimePolicyIndex(config.RuntimePolicyKindZone, scopeIndex, policyIndex),
				RuleID:     uint32(policyIndex + 1),
				Match:      policyMatchInfo(pol.Match),
```

Runtime trace:

1. First zone-pair policy has runtime ID 0 by construction.
2. `policiesHandler` sets `PolicyID: 0` for that real rule.
3. JSON encoding drops the field because the tag is `omitempty`.
4. `/api/v1/security/policies` consumers cannot join RT_FLOW/session telemetry `policy_id=0` to the first policy row without reconstructing compiler order locally.

Why it matters:

This undercuts the purpose of exposing runtime policy IDs. The first policy is a common high-priority rule, and the API hides its ID exactly where correlation matters.

Fix direction:

Use `*uint32` or an explicit `has_policy_id`/`default_policy` field for REST JSON. Keep synthetic default policies omitted, but emit `policy_id: 0` for real first rules.

### H02. REST match-policies silently omits `policy_id` for first-rule matches

Severity: Medium
Confidence: High
Labels: `bug`, `api`, `firewall`, `diagnostics`

Evidence:

`pkg/api/types.go:419-455`

```go
	type MatchPoliciesResult struct {
		Matched bool   `json:"matched"`
		Action  string `json:"action,omitempty"`

		// PolicyName is set only when a user-defined policy matched.
		PolicyName string `json:"policy_name,omitempty"`

		// PolicyID is the runtime policy ID assigned by the compiler. Present only when
		// matched.
		PolicyID uint32 `json:"policy_id,omitempty"`

		// Scope identifies whether the match came from a zone-pair, global, host-inbound,
		// or default-policy path.
		Scope string `json:"scope,omitempty"`
```

`pkg/api/security.go:554-567`

```go
	writeOK(w, http.StatusOK, MatchPoliciesResult{
		Matched:    true,
		Action:     strings.ToUpper(res.Action),
		PolicyName: res.PolicyName,
		Global:     res.Global,
		FromZone:   res.FromZone,
		ToZone:     res.ToZone,
		PolicyID:   res.PolicyID,
		Scope:      res.Scope,
		DefaultUsed: res.DefaultUsed,
		Source:     formatMatchPoliciesSource(res),
		Transport:  matchPoliciesTransport(query),
	})
```

Runtime trace:

1. Query matches the first policy in the first zone-pair scope.
2. `policymatch.Result.PolicyID` is 0 and `Matched` is true.
3. REST handler copies `PolicyID: 0` into the response.
4. JSON `omitempty` drops the key, so a matched first-policy response looks like no runtime ID was available.

Why it matters:

`show security match-policies` style tooling is used to verify exact rule selection. The REST response loses the join key for the highest-priority rule and differs from later rule IDs.

Fix direction:

Mirror H01: make the JSON field nullable/pointer-backed or include a separate presence flag. Add a raw JSON test asserting first-rule responses include `"policy_id":0`.

### H03. REST policy inventory tests claim policy ID coverage but never assert it

Severity: Medium
Confidence: High
Labels: `test-gap`, `api`, `firewall`

Evidence:

`pkg/api/security_policy_addr_inventory_3336_test.go:12-21`

```go
func TestSecurityPolicyInventoryIncludesPolicyAndRuleIDs(t *testing.T) {
	// Regression coverage for #3336: structured policy inventory must include
	// policy_id/rule_id so runtime RT_FLOW logs can be correlated back to the
	// configured rule.  The assertions fail if the fields are removed from the
	// REST inventory builders.
```

`pkg/api/security_policy_addr_inventory_3336_test.go:118-167`

```go
	if be.RuleID != 1 || ge.RuleID != 1 {
		t.Fatalf("expected rule_id=1 for both rows, got %d and %d", be.RuleID, ge.RuleID)
	}
```

Runtime trace:

1. The test name/comment says it protects both `policy_id` and `rule_id`.
2. The assertions check `RuleID` but do not check `PolicyID`.
3. A regression that removes or omits REST `policy_id` for the first rule can pass.

Why it matters:

This is why H01 can survive after the issue that supposedly added policy IDs. The test describes the invariant but does not pin it.

Fix direction:

Assert both parsed values and raw JSON key presence, including a first-rule ID 0 case and a non-zero case.

### H04. REST match-policies scope tests avoid the first-rule policy ID edge

Severity: Medium
Confidence: High
Labels: `test-gap`, `api`, `firewall`, `diagnostics`

Evidence:

`pkg/api/security_matchpolicies_scope_3331_test.go:24-50`

```go
	set security policies from-zone trust to-zone untrust policy allow match source-address any
	set security policies from-zone trust to-zone untrust policy allow match destination-address any
	set security policies from-zone trust to-zone untrust policy allow match application junos-ssh
	set security policies from-zone trust to-zone untrust policy allow then permit
	set security policies from-zone untrust to-zone trust policy allow-back match source-address any
	set security policies from-zone untrust to-zone trust policy allow-back match destination-address any
	set security policies from-zone untrust to-zone trust policy allow-back match application junos-ssh
```

`pkg/api/security_matchpolicies_scope_3331_test.go:61-72`

```go
	resp := matchScopeID(t, h, "from-zone=untrust&to-zone=trust&source-ip=198.51.100.10&destination-ip=10.0.0.10&destination-port=22&protocol=tcp")
	if !resp.Matched || resp.Scope != "zone-pair" || resp.PolicyID == 0 {
		t.Fatalf("expected zone-pair policy_id, got %+v", resp)
	}
```

Runtime trace:

1. The fixture includes a first trust->untrust policy that would have policy ID 0.
2. The test queries the later untrust->trust policy and asserts `PolicyID != 0`.
3. The raw JSON `omitempty` failure for ID 0 is never exercised.

Why it matters:

The scope test gives false confidence that all matched policies expose runtime IDs, while specifically routing around the edge that JSON cannot represent with the current tag.

Fix direction:

Add a trust->untrust query and assert the raw body contains `"policy_id":0` after fixing H02.

### H05. AppID catalog builder panics on nil zone-policy entries while strict validation nil-guards them

Severity: Medium
Confidence: High
Labels: `bug`, `appid`, `firewall`, `config-robustness`

Evidence:

`pkg/appid/runtime.go:60-85`

```go
	addPolicyApps := func(policies []*config.Policy) error {
		for _, pol := range policies {
			for _, appName := range pol.Match.Applications {
				if appName == "" || strings.EqualFold(appName, "any") {
					continue
				}
```

`pkg/appid/runtime.go:82-88`

```go
	for _, zpp := range cfg.Security.Policies {
		if err := addPolicyApps(zpp.Policies); err != nil {
			return nil, err
		}
	}
```

`pkg/config/compiler_validate_strict.go:3955-3972`

```go
	walk := func(policies []*Policy) {
		for _, pol := range policies {
			if pol == nil {
				continue
			}
			for _, appName := range pol.Match.Applications {
				addRef(appName)
			}
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		walk(zpp.Policies)
	}
```

Runtime trace:

1. A lenient/test/generated config contains a nil `*config.ZonePolicy` inside `cfg.Security.Policies`.
2. Strict validation would skip it.
3. `appid.CatalogNames` dereferences `zpp.Policies` without a nil guard.
4. Userspace app catalog build panics instead of returning a config error.

Why it matters:

Firewall config ingestion should fail closed with an actionable error, not panic in a runtime helper. The strict walker already documents the intended resilience.

Fix direction:

Match the strict walker: skip nil zone-policy entries and nil policies in `CatalogNames`, then add a regression test that a malformed/nil fixture does not panic.

### H06. AppID catalog builder panics on nil policy entries while strict validation nil-guards them

Severity: Medium
Confidence: High
Labels: `bug`, `appid`, `firewall`, `config-robustness`

Evidence:

`pkg/appid/runtime.go:60-75`

```go
	addPolicyApps := func(policies []*config.Policy) error {
		for _, pol := range policies {
			for _, appName := range pol.Match.Applications {
				if appName == "" || strings.EqualFold(appName, "any") {
					continue
				}
				if _, ok := BuiltinAppCatalog[appName]; !ok {
```

`pkg/config/compiler_validate_strict.go:3955-3964`

```go
	walk := func(policies []*Policy) {
		for _, pol := range policies {
			if pol == nil {
				continue
			}
			for _, appName := range pol.Match.Applications {
				addRef(appName)
			}
```

Runtime trace:

1. A zone-pair or global policy slice contains a nil `*Policy` entry.
2. Strict validation skips it.
3. `CatalogNames` dereferences `pol.Match` and panics.
4. `appid.BuildCatalog` propagates neither an error nor a clean validation failure.

Why it matters:

This creates a second panic path in the catalog builder. It is especially risky because `buildAppCatalogSnapshot` runs during userspace dataplane config application.

Fix direction:

Guard `pol == nil` in `CatalogNames` and add nil-policy coverage for both zone-pair and global policy slices.

### H07. Structured REST/gRPC policy inventory omits scheduler binding

Severity: Medium
Confidence: High
Labels: `feature-gap`, `api`, `grpc`, `firewall`, `vsrx-parity`

Evidence:

`pkg/config/types_security.go:289-298`

```go
	type Policy struct {
		Name                   string
		Description            string
		Match                  PolicyMatch
		Then                   PolicyThen
		Action                 string
		Log                    *PolicyLog
		SchedulerName          string
		Inactive               bool
		SourceAddressExcluded  bool
```

`pkg/grpcapi/server_show_zones.go:139-163`

```go
			pr := &pb.PolicyRule{
				Name:                       pol.Name,
				Description:                pol.Description,
				Action:                     pol.Action,
				SrcAddresses:               append([]string(nil), pol.Match.SourceAddresses...),
				DstAddresses:               append([]string(nil), pol.Match.DestinationAddresses...),
				Applications:               append([]string(nil), pol.Match.Applications...),
				Log:                        pol.Log != nil,
				Count:                      pol.Then.Count,
```

`pkg/api/security.go:164-178`

```go
			out = append(out, PolicyInfo{
				FromZone:   zpp.FromZone,
				ToZone:     zpp.ToZone,
				Name:       pol.Name,
				Action:     strings.ToUpper(pol.Action),
				PolicyID:   config.RuntimePolicyIndex(config.RuntimePolicyKindZone, scopeIndex, policyIndex),
				RuleID:     uint32(policyIndex + 1),
				Match:      policyMatchInfo(pol.Match),
```

Runtime trace:

1. A policy is bound to a scheduler via `SchedulerName`.
2. The compiler/userspace policy path has the field available.
3. REST and gRPC structured inventory drop the binding entirely.
4. Automation cannot tell that a permit/deny rule is time-gated without parsing raw config or CLI text.

Why it matters:

vSRX/Junos operational workflows expose scheduled policy state because time gating changes effective allow/deny behavior. Missing the binding makes structured APIs incomplete for firewall audits.

Fix direction:

Add `scheduler_name` to REST `PolicyInfo` and gRPC `PolicyRule`, populate it for zone-pair and global policies, and add API/gRPC tests.

### H08. Structured REST/gRPC policy inventory omits current scheduler inactive/effective state

Severity: Medium
Confidence: High
Labels: `feature-gap`, `api`, `grpc`, `firewall`, `vsrx-parity`

Evidence:

`pkg/dataplane/userspace/policies.go:379-396`

```go
	return userspace.PolicySnapshot{
		Name:                       pol.Name,
		Action:                     policyActionValue(pol.Action),
		SrcAddresses:               srcAddrs,
		DstAddresses:               dstAddrs,
		Applications:               append([]string(nil), pol.Match.Applications...),
		Logging:                    logging,
		CountEnabled:               pol.Then.Count,
		SchedulerName:              pol.SchedulerName,
		Inactive:                   pol.Inactive,
		SourceAddressExcluded:      pol.SourceAddressExcluded,
```

`proto/xpf/v1/xpf.proto:286-312`

```proto
message PolicyRule {
  string name = 1;
  string description = 2;
  string action = 3;
  repeated string src_addresses = 4;
  repeated string dst_addresses = 5;
  repeated string applications = 6;
  bool log = 7;
  bool count = 8;
  bool source_address_excluded = 9;
  bool destination_address_excluded = 10;
  bool log_session_init = 11;
  bool log_session_close = 12;
  uint32 policy_id = 13;
  uint32 rule_id = 14;
}
```

Runtime trace:

1. Scheduler evaluation can mark a policy inactive.
2. Userspace snapshots carry `Inactive`.
3. REST/gRPC policy inventory has no field for it.
4. A structured client can display a dormant rule as an active allow/deny rule.

Why it matters:

This is a correctness/operations gap for scheduled firewall policy audits: the API view can disagree with the effective dataplane behavior.

Fix direction:

Add an `inactive` or `effective` field to structured inventory and tests that a scheduled inactive rule reports its state.

### H09. Userspace snapshot summary `policy_count` counts zone-pair sets, not policies

Severity: Medium
Confidence: High
Labels: `bug`, `userspace-dataplane`, `observability`, `firewall`

Evidence:

`pkg/dataplane/userspace/builder.go:29-45`

```go
func BuildSnapshot(cfg *config.Config) (*Snapshot, error) {
	if cfg == nil {
		return nil, fmt.Errorf("userspace snapshot: nil config")
	}

	zoneCount := len(cfg.Security.Zones)
	policyCount := len(cfg.Security.Policies)
	globalPolicyCount := len(cfg.Security.GlobalPolicies)
```

`pkg/dataplane/userspace/builder.go:113-123`

```go
	return &Snapshot{
		Summary: SnapshotSummary{
			ZoneCount:             zoneCount,
			PolicyCount:           policyCount,
			GlobalPolicyCount:     globalPolicyCount,
			AddressBookCount:      addressBookCount,
```

`userspace-dp/src/protocol/snapshot.rs:20-35`

```rust
pub struct SnapshotSummary {
    pub zone_count: u32,
    pub policy_count: u32,
    pub global_policy_count: u32,
    pub address_book_count: u32,
    pub feed_set_count: u32,
    pub interface_binding_count: u32,
```

Runtime trace:

1. Config has one zone-pair with 100 policies.
2. `policyCount := len(cfg.Security.Policies)` records 1.
3. Rust receives `policy_count=1`, not 100.
4. Global-only configs can report `policy_count=0` even when effective global policies exist.

Why it matters:

Snapshot summaries are used as sanity/telemetry. A count named `policy_count` that actually means `zone_policy_set_count` hides missing policy publication and makes cross-plane audits weaker.

Fix direction:

Either rename the field to `zone_policy_set_count` or compute real policy rule count. Include a separate global count or total count with explicit semantics.

## Medium Confidence Findings

### M01. NAT-only application references are omitted from the AppID catalog when application-identification is disabled

Severity: Medium
Confidence: Medium
Labels: `feature-gap`, `appid`, `nat`, `firewall`

Evidence:

`pkg/appid/runtime.go:60-90`

```go
	addPolicyApps := func(policies []*config.Policy) error {
		for _, pol := range policies {
			for _, appName := range pol.Match.Applications {
				if appName == "" || strings.EqualFold(appName, "any") {
					continue
				}
				if _, ok := BuiltinAppCatalog[appName]; !ok {
					return nil
				}
				names[appName] = struct{}{}
			}
		}
		return nil
	}
```

`pkg/config/compiler_validate_strict.go:3974-3995`

```go
	walkNATRules := func(rs *NATRuleSet) {
		if rs == nil {
			return
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			addRef(rule.Match.Application)
		}
	}
	for _, rs := range cfg.Security.NAT.Source {
		walkNATRules(rs)
	}
```

Runtime trace:

1. Config uses `source/destination NAT match application junos-ssh` and no security policy references that app.
2. Strict validation accepts and validates the NAT application reference.
3. `CatalogNames(false)` walks only security policies/global policies.
4. The catalog omits the NAT-only application unless full AppID catalog publication is enabled.

Why it matters:

NAT application matching and security policy application matching should use a consistent app catalog. A NAT-only reference should not disappear from runtime introspection just because it is not also present in a policy.

Fix direction:

Have `CatalogNames(false)` share the strict reference walker or explicitly include NAT rule application references. Add a NAT-only catalog regression test.

### M02. AppID runtime parity test knowingly excludes NAT references, preserving the catalog drift

Severity: Medium
Confidence: Medium
Labels: `test-gap`, `appid`, `nat`, `firewall`

Evidence:

`pkg/appid/runtime_test.go:43-60`

```go
	// Scope note (#2187): the strict walk also collects source/destination-NAT
	// `match application` references, which CatalogNames does not. This fixture
	// carries NO NAT rules, so the two walks still coincide here. Adding a NAT
	// reference to this fixture would (correctly) break the equality -- the
	// NAT-reference path is exercised by the compiler-package tests instead.
	cfg.Security.Policies = []*config.ZonePolicy{{
		FromZone: "trust",
		ToZone:   "untrust",
```

Runtime trace:

1. The test wants runtime catalog and strict compiler references to coincide.
2. It explicitly avoids NAT references because they would break equality.
3. Compiler tests cover validation, not runtime catalog publication.
4. NAT-only runtime catalog omission remains unpinned.

Why it matters:

This is a fragile boundary between validation and dataplane publication. The test documents the drift but does not turn it into an issue or protection.

Fix direction:

Add a NAT fixture and decide the contract: either runtime catalog must include NAT refs, or docs/API must explicitly say catalog is policy-only. For router/firewall completeness, include NAT refs.

### M03. CLI `show security match-policies` usage omits source-port and ICMP selectors that the matcher supports

Severity: Low
Confidence: Medium
Labels: `bug`, `cli`, `firewall`, `diagnostics`

Evidence:

`pkg/cli/cli_show_security.go:368-395`

```go
		case "source-port":
			next, ok := needValue(i)
			if !ok {
				return nil
			}
			if err := parsePort(next, "source-port", &q.SrcPort); err != nil {
				fmt.Fprintln(c.OutOrStdout(), err.Error())
				return nil
			}
```

`pkg/cli/cli_show_security.go:440-449`

```go
	if fromZone == "" || toZone == "" {
		fmt.Println("usage: show security match-policies from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
		return nil
	}
```

Runtime trace:

1. Operator debugs a policy that matches a source port or ICMP type/code constrained app.
2. The parser supports `source-port`, `icmp-type`, and `icmp-code`.
3. The usage text shows only destination port and TCP/UDP protocol.
4. Operator may omit required selectors and get a false no-match/default result.

Why it matters:

Firewall diagnostics need to be precise. A debug tool that hides valid selectors encourages wrong conclusions about deny/allow behavior.

Fix direction:

Update usage/help text to include source port and ICMP selectors, with examples for TCP, UDP, ICMP, and ICMPv6.

### M04. AppID README documents a stale `ResolveSessionName` signature

Severity: Low
Confidence: Medium
Labels: `docs`, `appid`, `firewall`

Evidence:

`pkg/appid/README.md:25-34`

```md
- `ResolveSessionName(appNames map[uint16]string, cfg *config.Config, proto uint8, dstPort uint16, appID uint16) string`
  resolves session display names using the snapshot catalog, then runtime
  built-ins, then protocol/port fallbacks.
```

`pkg/appid/runtime.go:99-112`

```go
func ResolveSessionName(appNames map[uint16]string, cfg *config.Config, proto uint8, srcPort uint16, dstPort uint16, appID uint16) string {
	if appID != 0 {
		if name, ok := appNames[appID]; ok && name != "" {
			return name
		}
```

Runtime trace:

1. Docs describe a destination-port-only resolver.
2. Code now accepts source and destination ports.
3. Future callers may cargo-cult the old contract or miss source-port fallback behavior.

Why it matters:

The source-port dimension matters for diagnostics and protocol naming. Stale docs make later AppID/session display changes more error-prone.

Fix direction:

Update the README signature and describe the source-port fallback semantics.

### M05. Host-inbound diagnostic wording says local delivery proceeds even when later junos-host policy can drop it

Severity: Low
Confidence: Medium
Labels: `diagnostics`, `host-inbound`, `firewall`, `vsrx-parity`

Evidence:

`pkg/policymatch/policymatch.go:290-298`

```go
const (
	ScopeZonePair    = "zone-pair"
	ScopeGlobal      = "global"
	ScopeHostInbound = "host-inbound"
	ScopeDefault     = "default"

	HostInboundActionString = "LOCAL-DELIVERY"
)
```

`pkg/api/security.go:527-536`

```go
	if res.HostInboundUnmatched {
		writeOK(w, http.StatusOK, MatchPoliciesResult{
			Matched:              false,
			Action:               strings.ToUpper(res.Action),
			Scope:                res.Scope,
			DefaultUsed:          false,
			HostInboundUnmatched: true,
			Source:               formatMatchPoliciesSource(res),
```

`pkg/cli/cli_show_security.go:504-508`

```go
	case res.HostInboundUnmatched:
		fmt.Fprintf(c.OutOrStdout(), "host-inbound: local delivery proceeds\n")
```

Runtime trace:

1. Packet is host-bound and passes zone host-inbound service/protocol admission.
2. `match-policies` reports `LOCAL-DELIVERY` and CLI says local delivery proceeds.
3. A later junos-host/global policy or local-service control can still deny the packet.
4. The diagnostic can be read as final permit rather than stage permit.

Why it matters:

vSRX-style debugging separates host-inbound gate from policy evaluation. The current wording risks a false positive during deny/allow investigations.

Fix direction:

Rename the action/source to something like `HOST-INBOUND-ADMIT` or include `next_stage: junos-host-policy`. Update CLI wording accordingly.

### M06. Match-policies negative/default responses omit query zone context

Severity: Low
Confidence: Medium
Labels: `api`, `diagnostics`, `firewall`

Evidence:

`pkg/api/security.go:537-551`

```go
	if !res.Matched {
		writeOK(w, http.StatusOK, MatchPoliciesResult{
			Matched:      false,
			Action:       strings.ToUpper(res.Action),
			Scope:        res.Scope,
			DefaultUsed:  res.DefaultUsed,
			Source:       formatMatchPoliciesSource(res),
			Transport:    matchPoliciesTransport(query),
			DefaultAction: strings.ToUpper(res.DefaultAction),
		})
		return
	}
```

`pkg/api/types.go:433-446`

```go
	Scope string `json:"scope,omitempty"`

	// DefaultUsed is true when no explicit rule matched and default-policy handled the packet.
	DefaultUsed bool `json:"default_used,omitempty"`

	// FromZone/ToZone are filled for zone-pair policy matches.
	FromZone string `json:"from_zone,omitempty"`
	ToZone   string `json:"to_zone,omitempty"`
```

Runtime trace:

1. Operator queries `from-zone=A&to-zone=B` and gets default deny/no match.
2. Response omits `from_zone` and `to_zone` because they are only filled for matches.
3. A stored JSON log cannot prove which zone pair was tested without separately capturing the request URL.

Why it matters:

Negative firewall diagnostics are as important as positive matches. Auditors need request context in the response body, especially for API-driven tests.

Fix direction:

Echo normalized `from_zone` and `to_zone` for all match-policies responses, not only user-policy matches.

### M07. Match-policies response cannot explain which match dimension failed

Severity: Low
Confidence: Medium
Labels: `feature-gap`, `diagnostics`, `firewall`, `vsrx-parity`

Evidence:

`pkg/policymatch/policymatch.go:258-288`

```go
type Result struct {
	Matched              bool
	Action               string
	PolicyName           string
	PolicyID             uint32
	Global               bool
	DefaultUsed          bool
	Scope                string
	FromZone             string
	ToZone               string
	DefaultAction        string
	HostInboundUnmatched bool
}
```

`pkg/api/types.go:419-455`

```go
type MatchPoliciesResult struct {
	Matched bool   `json:"matched"`
	Action  string `json:"action,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
	PolicyID uint32 `json:"policy_id,omitempty"`
	Scope string `json:"scope,omitempty"`
```

Runtime trace:

1. Packet does not match any explicit rule.
2. The matcher knows each policy it evaluated but returns only default/no-match.
3. API/CLI cannot say whether the miss was source address, destination address, application, scheduler inactive, or zone scope.

Why it matters:

vSRX/Junos operators rely on match-policy diagnostics to isolate why a deny happened. A binary matched/default answer forces packet captures or manual config inspection.

Fix direction:

Add optional explain/debug output for first candidate misses and the failing dimension, gated behind a query flag so normal hot paths stay lean.

### M08. `PolicyRule` proto3 `policy_id` cannot distinguish unset from first-rule ID 0 in generic clients

Severity: Low
Confidence: Medium
Labels: `grpc`, `api`, `firewall`, `observability`

Evidence:

`proto/xpf/v1/xpf.proto:300-312`

```proto
  bool log_session_init = 11;
  bool log_session_close = 12;

  // Runtime policy ID assigned by the compiler and emitted in RT_FLOW session
  // telemetry.  Consumers can join GetPolicies rows to runtime events via this
  // value.
  uint32 policy_id = 13;

  // 1-based rule index inside the containing policy scope.
  uint32 rule_id = 14;
```

Runtime trace:

1. A first real rule has policy ID 0.
2. Proto3 scalar `uint32` defaults to 0 when absent.
3. Generic JSON/proto clients cannot distinguish absent ID from first-rule ID without relying on separate scope/default semantics.

Why it matters:

The gRPC field has the same semantic edge as REST, though binary consumers can often infer from `matched`/scope. For generated inventory rows, synthetic default vs first user rule needs a clear presence model.

Fix direction:

Use `optional uint32 policy_id` in proto3 or add an explicit `bool has_policy_id`, and document synthetic default behavior.

### M09. Accepted protocol numbers can display numerically because `ProtocolName` is not the inverse of protocol parsing

Severity: Low
Confidence: Medium
Labels: `observability`, `appid`, `firewall`, `vsrx-parity`

Evidence:

`pkg/appid/catalog.go:234-252`

```go
// ProtocolName returns the display name for a protocol number.  The mapping is
// intentionally narrow: it covers the protocols we have high-confidence service
// names for and leaves other IP protocol numbers as numeric fallback in session
// output.  It is NOT a complete inverse of ProtocolNumber, which resolves
// additional protocol names (ospf/egp/igmp/pim/ah/sctp/vrrp/...) that have no
// display mapping here.
func ProtocolName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
```

`pkg/appid/catalog.go:254-283`

```go
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 4:
		return "ipip"
	case 41:
		return "ipv6"
	default:
		return ""
	}
}
```

Runtime trace:

1. Policy/app parsing accepts names like OSPF, PIM, AH, SCTP, or VRRP.
2. Session display calls `ProtocolName` for protocol-only fallback.
3. These accepted protocols can appear as numeric protocol IDs rather than names.

Why it matters:

Firewall session output is operator-facing. vSRX-style troubleshooting expects recognizable protocol names for routing/security protocols.

Fix direction:

Add display names for all protocol names accepted by `ProtocolNumber`, or rename/document this as intentionally minimal and cover the resulting display in tests.

### M10. App catalog fallback under-labels common predefined apps when full AppID is disabled

Severity: Low
Confidence: Medium
Labels: `feature-gap`, `appid`, `firewall`, `vsrx-parity`

Evidence:

`pkg/appid/runtime.go:39-55`

```go
func CatalogNames(cfg *config.Config, includeAll bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	names := make(map[string]struct{})
	if includeAll {
		for name := range BuiltinAppCatalog {
			names[name] = struct{}{}
		}
		return sortedNames(names), nil
	}
```

`pkg/appid/catalog.go:104-126`

```go
	for _, name := range names {
		entry := BuiltinAppCatalog[name]
		rules := make([]CompiledRule, 0, len(entry.Rules))
		for _, rule := range entry.Rules {
			proto, ok := ProtocolNumber(rule.Protocol)
			if !ok {
				return nil, fmt.Errorf("appid catalog %s: unsupported protocol %q", name, rule.Protocol)
			}
```

Runtime trace:

1. Full app identification service is disabled.
2. Runtime catalog includes only referenced policy apps, not all built-ins.
3. Sessions for unreferenced-but-known services fall back to protocol/port or numeric names.

Why it matters:

This is defensible for footprint, but it creates observability divergence from vSRX-style predefined application naming. Operators may expect known apps to be named even when not policy-referenced.

Fix direction:

Decide contract explicitly. If footprint is the reason, document it and add an option to publish all built-ins for observability without enabling full AppID classification.

### M11. Policy inventory `Log` boolean can be ambiguous relative to effective log flags

Severity: Low
Confidence: Medium
Labels: `api`, `grpc`, `firewall`, `observability`

Evidence:

`pkg/grpcapi/server_show_zones.go:145-157`

```go
				Applications:               append([]string(nil), pol.Match.Applications...),
				Log:                        pol.Log != nil,
				Count:                      pol.Then.Count,
				SourceAddressExcluded:      pol.SourceAddressExcluded,
				DestinationAddressExcluded: pol.DestinationAddressExcluded,
				LogSessionInit:             pol.Log != nil && pol.Log.SessionInit,
				LogSessionClose:            pol.Log != nil && pol.Log.SessionClose,
```

`pkg/api/security.go:245-257`

```go
		Log:                       pol.Log != nil,
		Count:                     pol.Then.Count,
		SourceAddressExcluded:     pol.SourceAddressExcluded,
		DestinationAddressExcluded: pol.DestinationAddressExcluded,
		LogSessionInit:            pol.Log != nil && pol.Log.SessionInit,
		LogSessionClose:           pol.Log != nil && pol.Log.SessionClose,
```

Runtime trace:

1. Structured inventory sets `log=true` whenever a log block exists.
2. Effective event fields are separately `log_session_init` and `log_session_close`.
3. A lenient/imported config with a log block but no effective flags would show `log=true` but no events.

Why it matters:

Operator audits care about whether session-init/session-close logs will actually be generated, not only whether syntax created a log object.

Fix direction:

Either drop the ambiguous `log` field or define it as `session_init || session_close`. Keep detailed event flags as the authoritative fields.

## Low Confidence / Triage Findings

### L01. Synthetic default policy rows use empty address/application arrays that can be misread as match-none

Severity: Low
Confidence: Low
Labels: `api`, `firewall`, `observability`

Evidence:

`pkg/api/security.go:126-139`

```go
	out = append(out, PolicyInfo{
		FromZone:    "-",
		ToZone:      "-",
		Name:        "__default__",
		Action:      strings.ToUpper(action),
		Description: "Synthetic default policy used when no explicit security policy matches",
		Match: PolicyMatchInfo{
			SourceAddresses:      []string{},
			DestinationAddresses: []string{},
			Applications:         []string{},
```

Triage trace:

A structured client receives a default row whose match arrays are empty rather than `any`. In many APIs empty means match-none, not wildcard.

Why it matters:

Default policy semantics are security-critical. Ambiguous representation can lead dashboards or auditors to hide or misinterpret the default deny/permit row.

Fix direction:

Represent synthetic default matches as explicit `any` or add a `synthetic/default_policy` typed field that tells clients not to treat arrays literally.

### L02. Match-policies host-inbound response does not expose the service/protocol token that admitted local delivery

Severity: Low
Confidence: Low
Labels: `diagnostics`, `host-inbound`, `firewall`, `vsrx-parity`

Evidence:

`pkg/api/security.go:527-536`

```go
	if res.HostInboundUnmatched {
		writeOK(w, http.StatusOK, MatchPoliciesResult{
			Matched:              false,
			Action:               strings.ToUpper(res.Action),
			Scope:                res.Scope,
			DefaultUsed:          false,
			HostInboundUnmatched: true,
```

`pkg/policymatch/policymatch.go:259-288`

```go
type Result struct {
	Matched              bool
	Action               string
	PolicyName           string
	PolicyID             uint32
	Global               bool
	DefaultUsed          bool
	Scope                string
	FromZone             string
	ToZone               string
	DefaultAction        string
	HostInboundUnmatched bool
}
```

Triage trace:

Host-inbound debug says local delivery is admitted but cannot name whether the match was `ssh`, `ping`, `all`, a protocol bucket, or a system-services alias.

Why it matters:

vSRX-style audits often need to prove exactly which host-inbound permission admitted management-plane traffic.

Fix direction:

Return optional `host_inbound_service` or `host_inbound_protocol` in match diagnostics.

### L03. Structured APIs do not expose the effective default-policy as a typed scope separate from synthetic inventory rows

Severity: Low
Confidence: Low
Labels: `api`, `firewall`, `observability`

Evidence:

`pkg/api/security.go:126-139`

```go
	out = append(out, PolicyInfo{
		FromZone:    "-",
		ToZone:      "-",
		Name:        "__default__",
		Action:      strings.ToUpper(action),
		Description: "Synthetic default policy used when no explicit security policy matches",
```

`pkg/api/types.go:143-183`

```go
type PolicyInfo struct {
	FromZone string `json:"from_zone"`
	ToZone   string `json:"to_zone"`
	Name     string `json:"name"`
	Action   string `json:"action"`
```

Triage trace:

Default policy is encoded as a row named `__default__` with fake zones `-` rather than a typed default-policy record.

Why it matters:

Synthetic names are brittle for API clients and can collide with assumptions about configured policy names.

Fix direction:

Add `scope: default` / `synthetic: true` to inventory rows or move defaults to a dedicated field.

### L04. AppID runtime catalog has no single shared reference walker with strict validation

Severity: Low
Confidence: Low
Labels: `refactor`, `appid`, `firewall`, `modularity`

Evidence:

`pkg/appid/runtime.go:60-90`

```go
	addPolicyApps := func(policies []*config.Policy) error {
		for _, pol := range policies {
			for _, appName := range pol.Match.Applications {
				if appName == "" || strings.EqualFold(appName, "any") {
					continue
				}
```

`pkg/config/compiler_validate_strict.go:3946-3995`

```go
	refs := make(map[string]struct{})
	addRef := func(appName string) {
		if appName == "" || strings.EqualFold(appName, "any") {
			return
		}
		refs[appName] = struct{}{}
	}
```

Triage trace:

There are two manually maintained walkers with different nil behavior and different source coverage.

Why it matters:

This is the structural root behind M01/H05/H06. Firewall application semantics should have one authoritative reference enumerator.

Fix direction:

Create `config.WalkApplicationReferences` or an appid package helper that strict validation, runtime catalog, and tests all share.

### L05. Policy inventory and match-policies use different concepts of default policy action

Severity: Low
Confidence: Low
Labels: `api`, `firewall`, `diagnostics`

Evidence:

`pkg/api/security.go:129-136`

```go
		Name:        "__default__",
		Action:      strings.ToUpper(action),
		Description: "Synthetic default policy used when no explicit security policy matches",
```

`pkg/api/security.go:543-550`

```go
			DefaultUsed:  res.DefaultUsed,
			Source:       formatMatchPoliciesSource(res),
			Transport:    matchPoliciesTransport(query),
			DefaultAction: strings.ToUpper(res.DefaultAction),
```

Triage trace:

Inventory encodes default as a synthetic policy row; match-policies encodes it as `default_used/default_action` fields.

Why it matters:

Two structured representations increase client-side branching and make it easier for dashboards to get default behavior wrong.

Fix direction:

Normalize default policy representation across inventory and diagnostic APIs.

### L06. gRPC `GetPolicies` lacks a `scope` enum while REST inventory has implicit zone/global/default rows

Severity: Low
Confidence: Low
Labels: `grpc`, `api`, `firewall`, `observability`

Evidence:

`proto/xpf/v1/xpf.proto:286-312`

```proto
message PolicyRule {
  string name = 1;
  string description = 2;
  string action = 3;
  repeated string src_addresses = 4;
  repeated string dst_addresses = 5;
  repeated string applications = 6;
```

`pkg/grpcapi/server_show_zones.go:132-166`

```go
		zp := &pb.ZonePolicy{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for policyIndex, pol := range zpp.Policies {
			if pol == nil {
				continue
```

Triage trace:

The proto has `ZonePolicy` wrappers and `GlobalPolicies`, but individual `PolicyRule` has no explicit scope/typed default metadata. REST has its own implicit conventions.

Why it matters:

Cross-API parity suffers. A client normalizing REST and gRPC policy inventory has to infer scope structurally.

Fix direction:

Add scope/default metadata in the protobuf response or provide a uniform flattened policy inventory endpoint.

### L07. Rust snapshot summary accepts `policy_count` blindly without validating count relationships

Severity: Low
Confidence: Low
Labels: `userspace-dataplane`, `test-gap`, `observability`

Evidence:

`userspace-dp/src/protocol/snapshot.rs:20-35`

```rust
pub struct SnapshotSummary {
    pub zone_count: u32,
    pub policy_count: u32,
    pub global_policy_count: u32,
    pub address_book_count: u32,
    pub feed_set_count: u32,
    pub interface_binding_count: u32,
```

`pkg/dataplane/userspace/builder.go:113-123`

```go
		Summary: SnapshotSummary{
			ZoneCount:             zoneCount,
			PolicyCount:           policyCount,
			GlobalPolicyCount:     globalPolicyCount,
			AddressBookCount:      addressBookCount,
```

Triage trace:

Rust receives summary counts but no validation checks that the counts match actual vectors/maps in the snapshot.

Why it matters:

Summary count drift can hide publication bugs. For high-reliability routing/firewall appliances, schema invariants should fail loud.

Fix direction:

Add Rust-side or Go-side snapshot integrity tests that compare summary counts to decoded objects. Clarify whether counts are object-set counts or rule counts.

### L08. AppID catalog error path collapses unknown referenced apps into no catalog names instead of collecting all errors

Severity: Low
Confidence: Low
Labels: `appid`, `diagnostics`, `firewall`

Evidence:

`pkg/appid/runtime.go:66-76`

```go
				if _, ok := BuiltinAppCatalog[appName]; !ok {
					return nil
				}
				names[appName] = struct{}{}
			}
		}
		return nil
	}
```

`pkg/appid/catalog.go:93-101`

```go
	names, err := CatalogNames(cfg, cfg.Services.ApplicationIdentification)
	if err != nil {
		return nil, err
	}
```

Triage trace:

This specific snippet silently ignores unknown app names in `CatalogNames`; later strict validation may catch them, but the helper itself does not report which reference was skipped.

Why it matters:

If the helper is used outside strict compile order in future diagnostics/tests, unknown app refs disappear rather than becoming explicit warnings.

Fix direction:

Have `CatalogNames` either rely on prior strict validation by contract and document that, or return an aggregated error for unknown references.

### L09. Match-policies transport string falls back to numeric protocols but usage suggests named TCP/UDP only

Severity: Low
Confidence: Low
Labels: `cli`, `api`, `diagnostics`, `firewall`

Evidence:

`pkg/cli/cli_show_security.go:448-449`

```go
		fmt.Println("usage: show security match-policies from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
```

`pkg/api/security.go:574-592`

```go
func matchPoliciesTransport(q policymatch.Query) MatchPoliciesTransport {
	return MatchPoliciesTransport{
		Protocol:        q.Protocol,
		SourcePort:      q.SrcPort,
		DestinationPort: q.DstPort,
		ICMPType:        q.ICMPType,
		ICMPCode:        q.ICMPCode,
	}
}
```

Triage trace:

API and matcher support non-TCP/UDP transport dimensions; CLI usage narrows the mental model to TCP/UDP.

Why it matters:

Firewall policy debugging for ICMP, GRE, ESP, OSPF, and other protocols is core router functionality.

Fix direction:

Expand CLI help and docs to show protocol number/name support and ICMP selectors.

### L10. No focused API test for scheduler fields because the fields do not exist yet

Severity: Low
Confidence: Low
Labels: `test-gap`, `api`, `firewall`, `vsrx-parity`

Evidence:

`pkg/api/security_policy_addr_inventory_3336_test.go:118-167`

```go
	if !be.SourceAddressExcluded || be.DestinationAddressExcluded {
		t.Fatalf("expected both source/destination exclusion flags to be independent, got %+v", be)
	}
	if be.RuleID != 1 || ge.RuleID != 1 {
		t.Fatalf("expected rule_id=1 for both rows, got %d and %d", be.RuleID, ge.RuleID)
	}
```

`pkg/config/types_security.go:293-298`

```go
		SchedulerName          string
		Inactive               bool
		SourceAddressExcluded  bool
		DestinationAddressExcluded bool
```

Triage trace:

Policy API tests cover address exclusions/log/count/rule IDs but no scheduler binding or active/inactive state.

Why it matters:

Scheduled policies are a core firewall feature. Without structured test coverage, future API parity work can miss effective policy state again.

Fix direction:

Add tests after H07/H08 fields are introduced: configured scheduler name, inactive flag, and active policy behavior.

### L11. `Log` and scheduler omissions point to a wider issue: policy API structs are flat files rather than modular feature packages

Severity: Low
Confidence: Low
Labels: `refactor`, `api`, `firewall`, `modularity`

Evidence:

`pkg/api/security.go:150-178`

```go
			out = append(out, PolicyInfo{
				FromZone:   zpp.FromZone,
				ToZone:     zpp.ToZone,
				Name:       pol.Name,
				Action:     strings.ToUpper(pol.Action),
				PolicyID:   config.RuntimePolicyIndex(config.RuntimePolicyKindZone, scopeIndex, policyIndex),
```

`pkg/grpcapi/server_show_zones.go:139-163`

```go
			pr := &pb.PolicyRule{
				Name:                       pol.Name,
				Description:                pol.Description,
				Action:                     pol.Action,
```

Triage trace:

REST and gRPC independently hand-map policy fields, and both missed scheduler/effective-state semantics.

Why it matters:

This is exactly the kind of cross-surface drift that modularization should prevent. Firewall policy presentation should have one domain mapper used by REST/gRPC/CLI.

Fix direction:

Create a `pkg/security/policyview/` package with canonical policy view structs and conversion helpers, then adapt REST/gRPC/CLI to it.

## Suggested Issue Split

If converting this report into GitHub issues, I would split it as:

1. REST/gRPC policy identity presence: H01, H02, H03, H04, M08.
2. Structured scheduled-policy inventory parity: H07, H08, L10.
3. AppID catalog reference walker robustness/parity: H05, H06, M01, M02, L04, L08.
4. Userspace snapshot summary policy count semantics: H09, L07.
5. Match-policies diagnostic completeness: M03, M05, M06, M07, L02, L09.
6. Policy inventory representation cleanup/modularity: L01, L03, L05, L06, L11.
7. AppID display/docs cleanup: M04, M09, M10.

## Validation Commands Run

```sh
git status --short --branch
git pull --rebase
git rev-parse HEAD
ls -1 /tmp/codex-review*.md /tmp/agy-review*.md
rg -n "intrazone|host-inbound|policy_id|AppID|match-policies|scheduler|junos-host|default-policy|dynamic app|source-identity|application-services|url-category|reject|generated" /tmp/codex-review*.md /tmp/agy-review*.md
rg -n "policy_id|rule_id|SchedulerName|Inactive|CatalogNames|ResolveSessionName|HostInboundActionString|policy_count|ProtocolName|match-policies" pkg proto userspace-dp
```
