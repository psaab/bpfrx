# Codex Review Audit 125

Date: 2026-07-01
Repo: `/home/ps/git/codex-bpfrx`
HEAD: `bdb36a1f533f`
Mode: quota campaign, core firewall / vSRX policy behavior focus
Output: `/tmp/codex-review-125.md`

## Campaign Controls

- Ran `git pull --rebase`: already up to date.
- Read `/home/ps/git/agy-do-review-audit.txt` and followed its quota-campaign structure.
- Read prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` reports for duplicate suppression.
- Read repo issue/backlog docs: `docs/issues/issue-history.md`, `docs/feature-gaps.md`, `docs/authoritative-backlog.md`, `_Log.md`.
- Suppressed previously filed or recently fixed themes including host-inbound configured flag/display fixes, reject budget/counter work, AppID nil/NAT/scheduler/log omissions, static NAT shadowing, GC races, feed path leniency, policy_id positional issues, NAT64 fragments, and broad vSRX tracking issues.

## Open Issue Duplicate Boundaries

Open issues observed in the local docs/backlog include #739, #1359, #1365, #1703, #1924, #1925, #1926, #1958, #2008, #2115, #2197, #2261, #2354, #2387, #2562, #2852, #3075, #3226, #3292, #3395.

Duplicate-suppressed topics from current and prior review files:

- Broad vSRX parity umbrella (#2008).
- Flow identity and conntrack broadening (#2387).
- NAT64 non-first fragment cache (#2562).
- NAT allocator global mutex (#2852).
- Zone ID renumbering (#3075).
- Host-inbound `all` / `any-service` support (#3226).
- Flowless local delivery open behavior (#3292).
- Positional `policy_id` semantics (#3395).
- Existing host-inbound display/configured repairs in #3653/#3654/#3655.
- Existing reject action repairs in #3656/#3657.
- Existing AppID inventory/log/scheduler repairs in #3622/#3624/#3625/#3626.
- Static NAT scope overwrite repaired in #3605.

## Module Checklist

Inspected modules/features:

1. Remote CLI zone rendering: `cmd/cli/show.go`.
2. Remote CLI policy rendering: `cmd/cli/show.go`.
3. Remote CLI match-policies rendering: `cmd/cli/show.go`.
4. Local CLI policy detail and request simulator: `pkg/cli/cli_show_security.go`, `pkg/cli/cli_request.go`.
5. REST security policy inventory and match API: `pkg/api/security.go`, `pkg/api/types.go`.
6. gRPC policy inventory and text detail: `pkg/grpcapi/server_show_zones.go`, `pkg/grpcapi/server_show_policies_text.go`.
7. gRPC/protobuf policy model: `proto/xpf/v1/xpf.proto`.
8. Policy match simulator: `pkg/policymatch/policymatch.go`.
9. Host-inbound presentation core: `pkg/config/host_inbound_view.go`.
10. Policy compiler validation: `pkg/config/compiler_policy_match.go`, `pkg/config/compiler_security.go`.
11. Userspace dataplane policy counters and default-policy-log path: `userspace-dp/src/policy.rs`, `userspace-dp/src/protocol/snapshot.rs`.
12. Documentation/reference surfaces: `docs/junos-cli-reference.md`, `docs/config-schema.md`, `_Log.md`.

Negative results:

- Rust policy counters already document relaxed/eventual consistency and default counter snapshot behavior; I did not refile that (#3451-style concern).
- Default-policy-log reaches Rust snapshot/default verdict tests; the new residual is API/presenter visibility only, not dataplane enforcement.
- Scoped global policy display from #3357 appears covered on the explicit filtered surfaces; I did not refile the prior scoped-global display issue.
- Match-policies scheduler fail-closed behavior from #3414 appears closed; the residual is inventory ambiguity when scheduler state is unavailable.
- Reject action token ordering/counters are already covered by #3656/#3657 and were not duplicated.

## High Confidence Findings

### H01. gRPC text policy detail inverts address-exclusion semantics

Severity: High
Confidence: High
Labels: `policy`, `grpc`, `vsrx-parity`, `security`, `observability`

Evidence:

`pkg/grpcapi/server_show_policies_text.go:321-341`

```go
if srcs := displayStringsFromConfigRule(pol.Match.SourceAddresses); len(srcs) == 0 {
	fmt.Fprintln(b, "    Source addresses: any")
} else {
	fmt.Fprintf(b, "    Source addresses: %s\n", strings.Join(srcs, ", "))
}
if dsts := displayStringsFromConfigRule(pol.Match.DestinationAddresses); len(dsts) == 0 {
	fmt.Fprintln(b, "    Destination addresses: any")
} else {
	fmt.Fprintf(b, "    Destination addresses: %s\n", strings.Join(dsts, ", "))
}
```

Contrast with the local detail renderer:

`pkg/cli/cli_show_security.go:180-211`

```go
func printPolicyMatchAddresses(label string, items []string, excluded bool) {
	prefix := label
	if excluded {
		prefix += " (except)"
	}
	if len(items) == 0 {
		fmt.Printf("    %s: any\n", prefix)
		return
	}
	fmt.Printf("    %s: %s\n", prefix, strings.Join(items, ", "))
}
```

Runtime trace:

1. Configure a policy with `source-address bad-host` and `source-address-excluded`.
2. Runtime policy matching correctly treats the rule as "any source except bad-host".
3. Local CLI detail prints `Source addresses (except): bad-host`.
4. gRPC text detail prints `Source addresses: bad-host` with no `(except)` marker.
5. A remote operator reading the gRPC text output gets the opposite security meaning from the actual rule.

Why it matters:

This is not cosmetic. For deny/permit auditing, excluded address sets invert the meaning of the listed objects. A firewall policy detail surface that hides exclusion can cause an operator to approve or troubleshoot the wrong exposure.

Suggested fix:

Share the local policy-detail address presenter with gRPC text, or add explicit `(except)` rendering in `server_show_policies_text.go` for source and destination address sets.

---

### H02. Match-policies positive responses hide address-exclusion semantics

Severity: High
Confidence: High
Labels: `match-policies`, `api`, `grpc`, `cli`, `policy`, `vsrx-parity`

Evidence:

`proto/xpf/v1/xpf.proto:718-780`

```proto
message MatchPoliciesResponse {
  string policy_name = 1;
  string action = 2;
  repeated string src_addresses = 3;
  repeated string dst_addresses = 4;
  repeated string applications = 5;
  string error = 6;
  bool matched = 7;
```

`pkg/policymatch/policymatch.go:666-683`

```go
if len(rule.Match.SourceAddresses) > 0 {
	matched := addressListMatches(rule.Match.SourceAddresses, src)
	if rule.Match.SourceAddressExcluded {
		matched = !matched
	}
	if !matched {
		return false
	}
}
if len(rule.Match.DestinationAddresses) > 0 {
	matched := addressListMatches(rule.Match.DestinationAddresses, dst)
	if rule.Match.DestinationAddressExcluded {
```

`pkg/api/types.go:460-507`

```go
type MatchPoliciesResult struct {
	PolicyName       string   `json:"policy_name"`
	Action           string   `json:"action"`
	SourceAddresses  []string `json:"src_addresses"`
	DestAddresses    []string `json:"dst_addresses"`
	Applications     []string `json:"applications"`
	Matched          bool     `json:"matched"`
```

Runtime trace:

1. Configure `source-address bad-host` plus `source-address-excluded` on a permit rule.
2. Query match-policies for a source outside `bad-host`.
3. `ruleMatches` correctly inverts the address-list test and returns a positive match.
4. REST/gRPC/CLI match-policies output lists `src_addresses: [bad-host]` but exposes no excluded flag.
5. The simulator output appears to say the policy matched because the source was `bad-host`, when the actual reason was the opposite.

Why it matters:

Match-policies is an audit and change-validation tool. Losing exclusion flags makes it unsuitable for verifying policies that use Junos-style negated address terms.

Suggested fix:

Add `source_address_excluded` and `destination_address_excluded` to the match result model across `policymatch.Result`, REST, gRPC, and CLI renderers.

---

### H03. Remote `show security zones` silently suppresses policy inventory RPC failures

Severity: Medium
Confidence: High
Labels: `remote-cli`, `grpc`, `policy`, `observability`, `security`

Evidence:

`cmd/cli/show.go:492-499`

```go
func (c *XPFClient) showZones(ctx context.Context, args []string) error {
	resp, err := c.client.GetZones(ctx, &pb.GetZonesRequest{})
	if err != nil {
		return fmt.Errorf("get zones: %w", err)
	}
	polResp, _ := c.client.GetPolicies(ctx, &pb.GetPoliciesRequest{})
	policiesByZone := map[string][]*pb.PolicyRule{}
	if polResp != nil {
```

Runtime trace:

1. `GetZones` succeeds.
2. `GetPolicies` returns a transient internal error or authorization error.
3. The CLI discards the error with `_`.
4. The command prints zone information with an empty policy-reference section and exits successfully.
5. The operator sees apparently policy-free zones instead of a degraded/partial output warning.

Why it matters:

On a firewall, a partial policy view should fail loud. Silent omission biases operators toward underestimating what policies are installed and can hide control-plane failure during incident response.

Suggested fix:

Return the `GetPolicies` error, or print an explicit warning and mark policy references as unavailable. For automation, failing the command is safer.

---

### H04. gRPC text policy detail collapses session-init vs session-close logging into bare `log`

Severity: Medium
Confidence: High
Labels: `grpc`, `policy`, `logging`, `vsrx-parity`, `observability`

Evidence:

`pkg/grpcapi/server_show_policies_text.go:346-350`

```go
if pol.Log != nil {
	fmt.Fprintln(b, "    Then: log")
} else {
	fmt.Fprintf(b, "    Then: %s\n", policyActionLabel(pol.Then))
}
```

`pkg/cli/cli_show_security.go:273-283`

```go
logModes := make([]string, 0, 2)
if pol.LogSessionInit {
	logModes = append(logModes, "at-create")
}
if pol.LogSessionClose {
	logModes = append(logModes, "at-close")
}
if len(logModes) > 0 {
	fmt.Printf("    Session log: %s\n", strings.Join(logModes, ", "))
}
```

Runtime trace:

1. Configure a policy with `then log session-close` only.
2. The structured/local detail surfaces can represent close-only logging.
3. gRPC text detail prints only `Then: log`.
4. A remote operator cannot tell whether session-create logging, session-close logging, or both are enabled.

Why it matters:

Session-init and session-close logging have different operational cost and audit semantics. Collapsing them masks whether the appliance will log connection starts, closes, byte counters, or both.

Suggested fix:

Render the same `Session log: at-create, at-close` detail used by local CLI, and keep `Then: <action>` separate from logging modifiers.

---

### H05. gRPC text policy detail omits runtime policy index/ID used by logs and counters

Severity: Medium
Confidence: High
Labels: `grpc`, `policy`, `logging`, `observability`

Evidence:

`pkg/grpcapi/server_show_policies_text.go:310-317`

```go
ruleID := pol.Name
if ruleID == "" {
	ruleID = fmt.Sprintf("%s/%d", pol.TermName, i+1)
}
fmt.Fprintf(b, "  Policy: %s\n", pol.Name)
if pol.Description != nil && *pol.Description != "" {
	fmt.Fprintf(b, "    Description: %s\n", *pol.Description)
}
```

`pkg/cli/cli_show_security.go:251-258`

```go
header := fmt.Sprintf("  Policy: %s", policyName)
if pol.PolicyID != 0 {
	header += fmt.Sprintf(" (Index: %d)", pol.PolicyID)
}
fmt.Println(header)
if pol.Description != nil && *pol.Description != "" {
	fmt.Printf("    Description: %s\n", *pol.Description)
}
```

Runtime trace:

1. RT_FLOW/session logs reference a numeric policy ID.
2. Local CLI policy detail shows `(Index: N)` for correlation.
3. gRPC text detail computes a `ruleID` internally for counters but does not print policy ID/index.
4. Remote users cannot map flow logs or counter records back to the text policy detail row.

Why it matters:

Policy ID correlation is a core firewall operations workflow. Removing it from one detail surface creates a split-brain troubleshooting path between local and remote operators.

Suggested fix:

Print the policy index/ID in gRPC text detail using the same header format as local CLI. Consider printing stable `rule_id` separately when present.

---

### H06. REST/gRPC synthetic default-policy inventory rows omit default-policy-log state

Severity: Medium
Confidence: High
Labels: `api`, `grpc`, `policy`, `default-policy`, `logging`, `vsrx-parity`

Evidence:

`pkg/api/security.go:340-348`

```go
if cfg.Security.Policies.DefaultPolicy != nil {
	out = append(out, PolicyRule{
		Name:             "default-policy",
		Action:           cfg.Security.Policies.DefaultPolicy.Action,
		SourceAddresses:  []string{"any"},
		DestAddresses:    []string{"any"},
		Applications:     []string{"any"},
		PolicyID:         1,
```

`pkg/config/types_security.go:65-77`

```go
type DefaultPolicyLog struct {
	SessionInit  bool `json:"session_init,omitempty"`
	SessionClose bool `json:"session_close,omitempty"`
}

type DefaultPolicy struct {
	Action PolicyAction      `json:"action,omitempty"`
	Log    *DefaultPolicyLog `json:"log,omitempty"`
}
```

Runtime trace:

1. Configure `security policies default-policy permit-all` and `default-policy-log session-init`.
2. Dataplane snapshot carries the default policy log settings and Rust tests cover default verdict logging.
3. REST/gRPC policy inventory synthesize a default-policy row.
4. That row does not expose `LogSessionInit` or `LogSessionClose`.
5. Operators see a default policy that appears unlogged while the dataplane emits logs.

Why it matters:

Default-policy logging is operationally important because it covers fallback traffic not matched by explicit policies. Inventory that hides it can mislead audit tooling.

Suggested fix:

Populate `Log`, `LogSessionInit`, and `LogSessionClose` on synthetic default-policy rows in REST and gRPC inventory.

---

### H07. Structured policy inventory collapses scheduler-state-unavailable into `inactive=false`

Severity: Medium
Confidence: High
Labels: `api`, `grpc`, `scheduler`, `policy`, `observability`

Evidence:

`pkg/api/security.go:159-164`

```go
// If no scheduler accessor is wired, preserve the legacy inventory behavior
// and report rules as active. Runtime enforcement and match-policies both
// fail closed when a named scheduler cannot be resolved.
_, haveSched := schedState.(interface {
	SchedulerActive(string) (bool, bool)
})
```

`pkg/api/security.go:212-218`

```go
SchedulerName:              schedulerName,
Inactive:                   haveSched && policySchedulerInactive(schedState, schedulerName),
FromZone:                   pol.From,
ToZone:                     pol.To,
PolicyID:                   uint32(idx + 1),
RuleID:                     termName,
```

Runtime trace:

1. A policy has a named scheduler.
2. Inventory is requested before a scheduler accessor is wired or when scheduler state is unavailable.
3. The API reports `inactive=false` because `haveSched` is false.
4. Runtime/match-policies fail closed for unresolved named schedulers.
5. Inventory says the policy is active while the dataplane/simulator treat it as unavailable.

Why it matters:

This is a dangerous observability mismatch for scheduled firewall rules. An operator can see an active permit in inventory while traffic is denied because the schedule cannot be evaluated.

Suggested fix:

Add a `scheduler_state_known` / `scheduler_resolved` field, or represent unknown separately from inactive=false. CLI renderers should warn when scheduler state is unavailable.

---

### H08. Host-inbound rendering hides zone default-deny posture when any interface override exists

Severity: Medium
Confidence: High
Labels: `host-inbound`, `cli`, `vsrx-parity`, `security`, `test-gap`

Evidence:

`pkg/config/host_inbound_view.go:193-231`

```go
if len(v.ZoneServices) == 0 && len(v.ZoneProtocols) == 0 && len(v.Interfaces) == 0 {
	lines = append(lines, fmt.Sprintf("%sHost-inbound: default deny (%s)", prefix, stanzaLabel(v.ZoneConfigured)))
} else {
	if len(v.ZoneServices) > 0 {
		lines = append(lines, fmt.Sprintf("%sZone services: %s", prefix, strings.Join(v.ZoneServices, ", ")))
	}
	if len(v.ZoneProtocols) > 0 {
```

Runtime trace:

1. A zone has no zone-level host-inbound services/protocols.
2. One interface in the zone has an explicit host-inbound override allowing SSH.
3. Other interfaces in the same zone still inherit zone-level default deny.
4. `Render` enters the `else` branch because `len(v.Interfaces) > 0` and never prints zone default deny.
5. The display shows the override but not the deny posture for the rest of the zone.

Why it matters:

Host-inbound is a security boundary. A partial interface override should not erase the visible default posture for all non-overridden interfaces.

Suggested fix:

Render zone-level `default deny` whenever zone service/protocol lists are empty, even if interface overrides exist. Then render interface overrides below it.

---

### H09. Remote host-inbound wire model cannot distinguish absent stanza from explicit empty stanza

Severity: Medium
Confidence: High
Labels: `host-inbound`, `grpc`, `cli`, `vsrx-parity`, `observability`

Evidence:

`cmd/cli/show.go:468-489`

```go
// ZoneInfo currently only reports whether the security-zone exists, not whether
// host-inbound was explicitly configured at zone scope. Preserve the local
// display for populated zone-level lists and leave empty zones as "no stanza"
// until the server can expose that distinction.
view := config.HostInboundView{
	ZoneName: z.Name,
}
if len(services) > 0 || len(protocols) > 0 {
	view.ZoneConfigured = true
```

`proto/xpf/v1/xpf.proto:230-255`

```proto
// True when this zone exists in the committed security-zone configuration.
// Empty host-inbound lists with this flag set therefore mean an explicit
// default-deny zone, not an absent zone.
bool host_inbound_configured = 4;
repeated string interfaces = 5;
repeated HostInboundInterface host_inbound_interfaces = 6;
```

Runtime trace:

1. Zone A has no `host-inbound-traffic` stanza.
2. Zone B has an explicit empty `host-inbound-traffic {}` stanza.
3. Server sends both with no services/protocols; `host_inbound_configured` currently means the zone exists, not the host-inbound stanza exists.
4. Remote CLI must guess and leaves `ZoneConfigured=false` for empty lists.
5. Both render as `(no stanza)`, losing the explicit default-deny operator intent.

Why it matters:

The distinction is meaningful in Junos-style configuration review. An explicit empty stanza documents intentional host-inbound denial; absence can indicate inheritance/omission.

Suggested fix:

Extend `ZoneInfo` with explicit host-inbound provenance, for example `zone_host_inbound_configured` or an enum: absent, explicit-empty, explicit-populated.

---

### H10. Local `request security match-policies` output omits policy ID/scope details

Severity: Medium
Confidence: High
Labels: `cli`, `match-policies`, `policy`, `observability`, `vsrx-parity`

Evidence:

`pkg/cli/cli_request.go:324-352`

```go
if result.IsDefault {
	fmt.Printf("Default policy: %s\n", result.Action)
} else if result.Policy != nil {
	fmt.Printf("Policy: %s\n", result.Policy.Name)
	fmt.Printf("Action: %s\n", result.Action)
	fmt.Printf("Source addresses: %s\n", strings.Join(result.Policy.Match.SourceAddresses, ", "))
	fmt.Printf("Destination addresses: %s\n", strings.Join(result.Policy.Match.DestinationAddresses, ", "))
} else if result.GlobalPolicy != nil {
	fmt.Printf("Global policy: %s\n", result.GlobalPolicy.Name)
	fmt.Printf("Action: %s\n", result.Action)
```

Runtime trace:

1. An operator validates a policy path with local `request security match-policies`.
2. The command prints only policy/global-policy name and action.
3. It omits the numeric policy ID/index, stable rule ID, from/to scope for global results, scheduler state, and exclusion/log semantics.
4. The remote `show security match-policies` path is richer than this local request path.

Why it matters:

This is the local equivalent of Junos operational policy simulation. It should be suitable for correlating with RT_FLOW/session logs and verifying global/zone policy scope.

Suggested fix:

Bring local request output to parity with the richer match-policies response model after adding missing fields there. At minimum, print policy ID, scope, from/to zones, exclusion flags, scheduler state, and stable rule ID.

## Medium Confidence Findings

### M01. Remote `show security policies` non-detail drops address-exclusion fields carried by gRPC

Severity: Medium
Confidence: Medium
Labels: `remote-cli`, `policy`, `vsrx-parity`, `observability`

Evidence:

`cmd/cli/show.go:564-574`

```go
renderRule := func(rule *pb.PolicyRule) {
	fmt.Printf("Rule: %s\n", rule.Name)
	if rule.Description != nil && *rule.Description != "" {
		fmt.Printf("  Description: %s\n", *rule.Description)
	}
	fmt.Printf("  Match: src=%v dst=%v app=%v\n", rule.SourceAddresses, rule.DestAddresses, rule.Applications)
	fmt.Printf("  Action: %s\n", rule.Action)
	if rule.HitPackets > 0 {
```

`proto/xpf/v1/xpf.proto:297-309`

```proto
repeated string source_addresses = 4;
repeated string destination_addresses = 5;
repeated string applications = 6;
string action = 7;
uint64 hit_packets = 8;
uint64 hit_bytes = 9;
bool source_address_excluded = 10;
bool destination_address_excluded = 11;
```

Runtime trace:

1. Server sends `source_address_excluded=true` or `destination_address_excluded=true`.
2. Remote CLI `show security policies` renders only raw source/destination arrays.
3. The user sees the same line for inclusive and exclusive address matches.
4. Non-detail output can misrepresent permit/deny reachability.

Why it matters:

Even non-detail policy output should not invert firewall semantics. If space is a concern, it should annotate `(except)` next to source/destination lists.

Suggested fix:

Use a shared address-list renderer for remote brief/detail surfaces and include `(except)` when exclusion flags are set.

---

### M02. Remote `show security policies` non-detail omits log mode and session logging state

Severity: Medium
Confidence: Medium
Labels: `remote-cli`, `policy`, `logging`, `observability`

Evidence:

`cmd/cli/show.go:564-574`

```go
fmt.Printf("  Match: src=%v dst=%v app=%v\n", rule.SourceAddresses, rule.DestAddresses, rule.Applications)
fmt.Printf("  Action: %s\n", rule.Action)
if rule.HitPackets > 0 {
	fmt.Printf("  Hits: %d packets / %d bytes\n", rule.HitPackets, rule.HitBytes)
}
```

`proto/xpf/v1/xpf.proto:310-318`

```proto
bool log = 12;
bool log_session_init = 13;
bool log_session_close = 14;
bool count = 15;
string term_name = 16;
string term_description = 17;
```

Runtime trace:

1. Server inventory carries log/session-init/session-close flags.
2. Remote non-detail renderer prints only action and optional hits.
3. A logged permit rule appears identical to an unlogged permit rule until detail is used.
4. A session-close-only rule is indistinguishable from session-init logging.

Why it matters:

Logging policy is part of the security contract and has performance impact. Hiding it in the default remote policy view weakens auditability.

Suggested fix:

Print concise logging metadata in the default remote policy view, e.g. `Log: at-create, at-close`.

---

### M03. Remote `show security policies` non-detail omits scheduler and inactive state

Severity: Medium
Confidence: Medium
Labels: `remote-cli`, `scheduler`, `policy`, `vsrx-parity`

Evidence:

`cmd/cli/show.go:564-574`

```go
fmt.Printf("  Match: src=%v dst=%v app=%v\n", rule.SourceAddresses, rule.DestAddresses, rule.Applications)
fmt.Printf("  Action: %s\n", rule.Action)
if rule.HitPackets > 0 {
	fmt.Printf("  Hits: %d packets / %d bytes\n", rule.HitPackets, rule.HitBytes)
}
```

`proto/xpf/v1/xpf.proto:327-339`

```proto
optional string policy_id = 21;
optional string rule_id = 22;
string scheduler_name = 23;
bool inactive = 24;
}
```

Runtime trace:

1. Server sends `scheduler_name` and `inactive=true` for a scheduled policy outside its active window.
2. Remote CLI prints `Action: permit` with no inactive/scheduler annotation.
3. The operator sees an apparently active permit rule that runtime enforcement will skip or deny through scheduler fail-closed behavior.

Why it matters:

Scheduled policy status directly changes whether traffic is allowed. It should not be hidden from the default policy view.

Suggested fix:

Print `Scheduler: <name> (inactive)` or at least `Inactive: true` in remote policy rendering.

---

### M04. Remote `show security policies` non-detail omits `then count` state when counters are zero

Severity: Low
Confidence: Medium
Labels: `remote-cli`, `policy`, `observability`, `test-gap`

Evidence:

`cmd/cli/show.go:568-574`

```go
fmt.Printf("  Action: %s\n", rule.Action)
if rule.HitPackets > 0 {
	fmt.Printf("  Hits: %d packets / %d bytes\n", rule.HitPackets, rule.HitBytes)
}
fmt.Println()
}
```

`proto/xpf/v1/xpf.proto:310-316`

```proto
bool log = 12;
bool log_session_init = 13;
bool log_session_close = 14;
bool count = 15;
string term_name = 16;
string term_description = 17;
```

Runtime trace:

1. A newly installed policy has `then count` but has not matched packets yet.
2. Server sends `count=true`, `hit_packets=0`, `hit_bytes=0`.
3. Remote CLI prints neither `Count: enabled` nor zero hits.
4. The operator cannot distinguish counted-but-idle from not-counted.

Why it matters:

Counter enablement is part of planned observability. Silent zero-state hides whether instrumentation is configured before traffic arrives.

Suggested fix:

Print count state whenever `rule.Count` is true, even with zero hits.

---

### M05. Match-policies responses lack stable `rule_id` even though policy inventory carries it

Severity: Low
Confidence: Medium
Labels: `match-policies`, `api`, `grpc`, `policy`, `observability`

Evidence:

`proto/xpf/v1/xpf.proto:327-339`

```proto
optional string policy_id = 21;
optional string rule_id = 22;
string scheduler_name = 23;
bool inactive = 24;
}
```

`proto/xpf/v1/xpf.proto:760-780`

```proto
optional string policy_id = 14;
bool default_used = 15;
string queried_from_zone = 16;
string queried_to_zone = 17;
repeated string queried_from_zones = 18;
repeated string queried_to_zones = 19;
}
```

Runtime trace:

1. Policy inventory exposes stable `rule_id`.
2. Match-policies returns only optional numeric/string `policy_id`.
3. The operator cannot correlate a simulator hit to the stable rule identifier carried by inventory.
4. If policy order changes, the positional/numeric correlation is weaker than the stable term/rule ID.

Why it matters:

Policy simulation should produce an identifier that survives reorder and can be joined to inventory, logs, and tests.

Suggested fix:

Add `rule_id` to `MatchPoliciesResponse`, REST `MatchPoliciesResult`, and CLI output.

---

### M06. Compiler unsupported-tail guard can miss global `from-zone` / `to-zone` tokens when they appear under `match application`

Severity: Medium
Confidence: Medium-Low
Labels: `config`, `policy`, `compiler`, `vsrx-parity`, `security`

Evidence:

`pkg/config/compiler_policy_match.go:117-121`

```go
var unsupportedPolicyMatchLeaves = []string{
	"dynamic-application",
	"url-category",
	"source-identity",
}
```

`pkg/config/compiler_security.go:672-679`

```go
case "application":
	if m.Keys[1] == "any" {
		pol.Match.Applications = []ApplicationRef{{Type: MatchValueAny}}
	} else {
		for _, a := range m.Keys[1:] {
			pol.Match.Applications = append(pol.Match.Applications, ApplicationRef{Name: a})
```

Runtime trace:

1. A malformed/global policy line places `from-zone` or `to-zone` after `match application`.
2. The unsupported-tail checker only rejects dynamic-application, url-category, and source-identity.
3. `compilePolicy` treats every token after `application` as an application name.
4. If application objects with those names exist, the intended zone scoping token is swallowed as an application ref and the global zone scope remains broad.

Why it matters:

This is an adversarial parser-edge concern: reserved match keywords should not be accepted as application operands merely because a same-named application object exists.

Suggested fix:

Reject `from-zone` and `to-zone` when they appear in the wrong grammar position, and add tests for malformed global policy tails.

## Low Confidence / Design and Coverage Findings

### L01. Missing gRPC text policy-detail regression tests for exclusion, logging, and IDs

Severity: Medium
Confidence: Low
Labels: `test-gap`, `grpc`, `policy`, `vsrx-parity`

Evidence:

`pkg/grpcapi/server_show_policies_text.go:321-350`

```go
if dsts := displayStringsFromConfigRule(pol.Match.DestinationAddresses); len(dsts) == 0 {
	fmt.Fprintln(b, "    Destination addresses: any")
} else {
	fmt.Fprintf(b, "    Destination addresses: %s\n", strings.Join(dsts, ", "))
}
if pol.Log != nil {
	fmt.Fprintln(b, "    Then: log")
} else {
```

Trace:

The structured inventory path has tests for richer policy fields from prior fixes, but the gRPC text renderer retains independent formatting logic. The current omissions above would have been caught by a golden test covering excluded source/destination, session-init/session-close, and policy ID.

Why it matters:

The gRPC text path is a separate user-visible policy detail surface. It can drift from local CLI and structured inventory without tests.

Suggested fix:

Add golden tests for gRPC `policies-detail` text with excluded address sets, both log modes, scheduler state, and policy ID/index.

---

### L02. Missing remote CLI tests for rich `PolicyRule` metadata in `show security policies`

Severity: Low
Confidence: Low
Labels: `test-gap`, `remote-cli`, `policy`

Evidence:

`cmd/cli/show.go:564-574`

```go
renderRule := func(rule *pb.PolicyRule) {
	fmt.Printf("Rule: %s\n", rule.Name)
	if rule.Description != nil && *rule.Description != "" {
		fmt.Printf("  Description: %s\n", *rule.Description)
	}
	fmt.Printf("  Match: src=%v dst=%v app=%v\n", rule.SourceAddresses, rule.DestAddresses, rule.Applications)
```

Trace:

The renderer receives `PolicyRule` metadata but only formats a subset. A fake gRPC client test with every metadata bit set would expose each dropped field and lock the intended default output.

Why it matters:

Remote CLI is the primary operational surface for structured daemon data. Rich metadata should not silently disappear during presentation.

Suggested fix:

Add tests for `showPoliciesFiltered` with exclusion, log modes, scheduler inactive, count, policy ID, and global/default rules.

---

### L03. Missing host-inbound presenter test for mixed interface override plus zone default-deny posture

Severity: Medium
Confidence: Low
Labels: `test-gap`, `host-inbound`, `security`

Evidence:

`pkg/config/host_inbound_view.go:193-203`

```go
if len(v.ZoneServices) == 0 && len(v.ZoneProtocols) == 0 && len(v.Interfaces) == 0 {
	lines = append(lines, fmt.Sprintf("%sHost-inbound: default deny (%s)", prefix, stanzaLabel(v.ZoneConfigured)))
} else {
	if len(v.ZoneServices) > 0 {
		lines = append(lines, fmt.Sprintf("%sZone services: %s", prefix, strings.Join(v.ZoneServices, ", ")))
	}
```

Trace:

Current presenter logic distinguishes an entirely empty view from a view with interface overrides. There should be a regression test for a zone with no zone-level services, at least two interfaces, and one interface override, proving non-overridden interfaces still show zone default deny.

Why it matters:

Without this test, a security posture omission can persist across local/remote host-inbound display work.

Suggested fix:

Add a host-inbound view test for the mixed override/default posture and update rendering accordingly.

---

### L04. Policy detail rendering should be factored into a shared module, not duplicated by surface

Severity: Low
Confidence: Low
Labels: `refactor`, `modularity`, `policy`, `cli`, `grpc`

Evidence:

`pkg/cli/cli_show_security.go:180-211`

```go
func printPolicyMatchAddresses(label string, items []string, excluded bool) {
	prefix := label
	if excluded {
		prefix += " (except)"
	}
	if len(items) == 0 {
		fmt.Printf("    %s: any\n", prefix)
```

`pkg/grpcapi/server_show_policies_text.go:321-341`

```go
if srcs := displayStringsFromConfigRule(pol.Match.SourceAddresses); len(srcs) == 0 {
	fmt.Fprintln(b, "    Source addresses: any")
} else {
	fmt.Fprintf(b, "    Source addresses: %s\n", strings.Join(srcs, ", "))
}
```

Trace:

Local CLI and gRPC text both render policy detail, but each owns custom formatting. One path knows about `(except)` and session logging detail; the other does not. This is classic drift from duplicated presentation logic.

Why it matters:

Security policy display is too important to fork across surfaces. Modularity here should be `policy/render/*.go`, not more `show_policy_foo.go` duplication.

Suggested fix:

Create a shared policy detail presenter package or module directory consumed by local CLI, remote CLI, and gRPC text rendering.

---

### L05. Match-policies result model should reuse or embed a policy summary instead of copying partial fields

Severity: Low
Confidence: Low
Labels: `refactor`, `api`, `grpc`, `match-policies`, `policy`

Evidence:

`pkg/api/types.go:153-164`

```go
type PolicyRule struct {
	Name                       string   `json:"name"`
	TermName                   string   `json:"term_name,omitempty"`
	FromZone                   string   `json:"from_zone,omitempty"`
	ToZone                     string   `json:"to_zone,omitempty"`
	Description                string   `json:"description,omitempty"`
```

`pkg/api/types.go:460-470`

```go
type MatchPoliciesResult struct {
	PolicyName       string   `json:"policy_name"`
	Action           string   `json:"action"`
	SourceAddresses  []string `json:"src_addresses"`
	DestAddresses    []string `json:"dst_addresses"`
	Applications     []string `json:"applications"`
```

Trace:

Policy inventory and match-policies maintain independent, partially overlapping structs. The match result has already fallen behind policy inventory for exclusion flags, log modes, scheduler data, and stable rule IDs.

Why it matters:

This creates recurring parity bugs between inventory and simulation surfaces.

Suggested fix:

Introduce a shared `policy/summary` model that match-policies can embed or reference, with explicit fields for match semantics and operational metadata.

---

### L06. Host-inbound wire model needs provenance, not overloaded `host_inbound_configured`

Severity: Low
Confidence: Low
Labels: `refactor`, `host-inbound`, `grpc`, `api`, `vsrx-parity`

Evidence:

`proto/xpf/v1/xpf.proto:230-255`

```proto
// True when this zone exists in the committed security-zone configuration.
// Empty host-inbound lists with this flag set therefore mean an explicit
// default-deny zone, not an absent zone.
bool host_inbound_configured = 4;
repeated string interfaces = 5;
repeated HostInboundInterface host_inbound_interfaces = 6;
```

Trace:

The field name suggests host-inbound configuration, but the comment says it means the zone exists. Remote CLI then cannot reconstruct absent vs explicit empty host-inbound state.

Why it matters:

Protocol fields with overloaded semantics force every consumer to guess. This already caused display compromises.

Suggested fix:

Replace or augment the boolean with explicit provenance: `HOST_INBOUND_ABSENT`, `HOST_INBOUND_EXPLICIT_EMPTY`, `HOST_INBOUND_EXPLICIT_POPULATED`, plus interface-level provenance if needed.

---

### L07. Host-inbound token deduplication is case-sensitive while map lookups normalize elsewhere

Severity: Low
Confidence: Low
Labels: `host-inbound`, `cli`, `config`, `test-gap`

Evidence:

`pkg/config/host_inbound_view.go:18-42`

```go
// UnionHostInboundTokens returns a sorted, de-duplicated union of the values in
// the supplied maps. Empty keys are ignored and value casing is preserved.
func UnionHostInboundTokens(maps ...map[string]HostInboundNamedMatch) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, mp := range maps {
```

Trace:

1. The presenter preserves case and deduplicates using the raw display string.
2. Other config paths tend to normalize names for map lookups.
3. If mixed-case service/protocol names enter from imported config or future API paths, the display can show duplicate logical tokens such as `SSH, ssh`.
4. This is low confidence because the parser may normalize enough paths today.

Why it matters:

A security display should not imply two distinct services when the runtime treats them as one logical service.

Suggested fix:

Normalize dedup keys while preserving the first display form, and add a mixed-case fixture if the grammar permits it.

## Suggested Issue Split

1. Fix gRPC text policy detail parity: address `(except)`, session log modes, policy index/rule ID.
2. Extend match-policies result schema for excluded address flags, stable rule ID, scheduler/log metadata.
3. Fix remote policy renderers to display all security-relevant `PolicyRule` metadata.
4. Expose default-policy-log on synthetic default-policy inventory rows.
5. Add scheduler-state-known/unknown semantics to policy inventory.
6. Fix host-inbound provenance/default-deny rendering gaps.
7. Harden policy compiler grammar validation for misplaced global `from-zone`/`to-zone` tokens.
8. Refactor policy presentation into a shared `policy/render` module with golden tests.

## Finding Count

- High confidence: 10
- Medium confidence: 6
- Low confidence: 7
- Total non-duplicate candidates: 23
