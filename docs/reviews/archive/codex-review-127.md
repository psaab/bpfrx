# Codex Review Audit 127

Whoami: codex
Output: `/tmp/codex-review-127.md`
Repo: `/home/ps/git/codex-bpfrx`
Base commit inspected: `763295a6224c`
Sync: `git pull --rebase` returned `Already up to date.`

## Campaign Contract

This was run as a quota campaign, not a best-findings pass. I read the prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` files for duplicate suppression, then inspected current repo docs/logs and code. I intentionally did not re-report the prior findings around intrazone default policy, host-inbound display, match-policies policy ID/scope, local/remote global/default zone-detail gaps already fixed by #3658, scheduler fail-open already fixed by #3414, reject ordering already fixed by #3656/#3661, or signed port commit/runtime parser drift already closed by #3606.

The focus for this run was core vSRX firewall behavior: zone-pair/global/default policy evaluation, host-inbound enforcement, match/test-policy diagnostics, reject behavior, and observability surfaces that decide whether packets are allowed or denied.

## Module Checklist

Inspected modules/features:

1. Go config policy model and global-zone helper: `pkg/config/types_security.go`, global policy compiler tests.
2. Rust userspace policy global scope implementation: `userspace-dp/src/policy.rs`.
3. Policy simulator core: `pkg/policymatch/policymatch.go`, port/ICMP tests, scheduler tests.
4. Local CLI zone and policy diagnostics: `pkg/cli/cli_show_security_zones.go`, `pkg/cli/cli_show_security.go`, `pkg/cli/cli_request.go`.
5. gRPC text renderers: `pkg/grpcapi/server_show_zones_text.go`, `pkg/grpcapi/server_show_firewall.go`.
6. Remote CLI control client renderers: `cmd/cli/show.go`.
7. REST policy/match APIs and wire types: `pkg/api/security.go`, `pkg/api/types.go`.
8. gRPC protobuf match-policies contract: `proto/xpf/v1/xpf.proto`.
9. REST/Prometheus global and host-inbound stats: `pkg/api/stats.go`, `pkg/api/metrics_counters.go`, `pkg/api/metrics_descriptors.go`.
10. Host-inbound zone view/lifeline modeling: `pkg/dataplane/userspace/zones.go`.
11. Rust userspace reject reply synthesis/rate limiting: `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`, `userspace-dp/src/afxdp/icmp_ratelimit.rs`.
12. Repo docs for recently closed issues: `docs/config-schema.md`, issue closeout/log markdown found by repo search.

Negative result notes:

- I did not find a new issue in the runtime Rust global-policy match itself: explicit `any` is correctly resolved to `GlobalZoneScope::Any`.
- I did not find a new issue in REST/gRPC policy inventory scheduler fields: `scheduler_name` and `inactive` are present on `PolicyRule`.
- I did not find a new issue in the #3656/#3661 per-source reject counters themselves: the policy/filter source counters are wired and tested. The remaining reject findings below are rate-sharing/design issues, not counter wiring regressions.

## High Confidence Findings

### H01. Explicit `any` global policies are hidden from local/gRPC zone-detail summaries

Severity: High
Confidence: High
Labels: `bug`, `security-observability`, `vsrx-parity`

Evidence:

```go
// pkg/config/types_security.go:353-357
func GlobalPolicyAppliesToZone(m PolicyMatch, zone string) bool {
    asSource := m.FromZone == "" || m.FromZone == zone
    asDest := m.ToZone == "" || m.ToZone == zone
    return asSource || asDest
}
```

Runtime treats both omitted and explicit `any` as all-zones:

```rust
// userspace-dp/src/policy.rs:801-829
/// - Empty (omitted) -> `Any`
/// - Explicit `"any"` -> `Any` as well...
fn build_global_zone_scope(... name: &str, ...) -> Result<GlobalZoneScope, SnapshotIntegrityError> {
    if name.is_empty() || name == "any" {
        return Ok(GlobalZoneScope::Any);
    }
```

The match-policies helper also knows this:

```go
// pkg/policymatch/policymatch.go:585-592
func GlobalPolicyAppliesToZonePair(matchFrom, matchTo, filterFrom, filterTo string) bool {
    axisApplies := func(scope, filter string) bool {
        if filter == "" || scope == "" || scope == "any" {
            return true
        }
        return scope == filter
    }
```

Runtime trace:

1. Configure `policy global policy g match from-zone any match to-zone untrust then deny`.
2. The compiler preserves `FromZone == "any"` and Rust enforces it as all source zones.
3. `show security zones detail trust` calls `GlobalPolicyAppliesToZone(g.Match, "trust")`.
4. `asSource` is false because `"any" != "" && "any" != "trust"`.
5. If `to-zone` is scoped to `untrust`, `asDest` is also false, so the global deny is omitted from the `trust` audit even though it applies to trust-originated traffic.

Why it matters:

The new #3658 zone detail summary exists so zone-centric audits cannot miss global policies. This bug hides a real global rule on explicit-Junos `any` configs, so the operator can believe a zone has no applicable global deny/permit.

Fix:

Make `GlobalPolicyAppliesToZone` share the same wildcard semantics as `policymatch.GlobalPolicyAppliesToZonePair`, or call that helper with an empty filter axis. Treat `""` and `"any"` identically.

### H02. Zone-detail policy-tier tests do not cover explicit `any`

Severity: High
Confidence: High
Labels: `test-gap`, `security-observability`, `vsrx-parity`

Evidence:

```go
// pkg/cli/cli_show_security_zones_policy_tiers_3658_test.go:22-25
// globalOnlyZoneCLIStore builds a config whose zone `dmz` has NO zone-pair
// policy but is covered by an UNSCOPED global permit, plus a SCOPED global
// (trust -> untrust) that must NOT leak into dmz's detail.
```

```go
// pkg/cli/cli_show_security_zones_policy_tiers_3658_test.go:121-128
if !strings.Contains(block, "[global] any -> any: open-global (permit)") {
    t.Fatalf("dmz detail missing unscoped global tier line ...")
}
if strings.Contains(block, "scoped-block") {
    t.Fatalf("dmz detail leaked scoped trust->untrust global ...")
}
```

Compiler tests explicitly preserve the dangerous case:

```go
// pkg/config/compiler_policy_global_zone_3148_test.go:121-133
cmds = append(cmds,
    "set security policies global policy anyfrom match from-zone any",
    "set security policies global policy anyfrom match to-zone untrust")
...
if len(cfg.Security.GlobalPolicies) != 1 || cfg.Security.GlobalPolicies[0].Match.FromZone != "any" {
    t.Fatalf("explicit `any` not preserved verbatim: %+v", cfg.Security.GlobalPolicies)
}
```

Runtime trace:

The local and gRPC zone-detail tests exercise omitted-any (`open-global`) and concrete scoped rules (`trust -> untrust`), but not explicit `from-zone any` / `to-zone any`. The helper bug in H01 survives because no test asserts an explicit `any` scoped global appears under every affected zone.

Why it matters:

This is not a speculative edge case: the compiler has a dedicated explicit-any test because it is Junos-compatible syntax. The new summary should pin it.

Fix:

Add local and gRPC text zone-detail cases for `match from-zone any to-zone untrust`, asserting it appears for source zones and destination zone, and does not disappear behind the omitted-any-only path.

### H03. Local/gRPC zone-detail summaries print scheduler-bound policies as active

Severity: High
Confidence: High
Labels: `bug`, `security-observability`, `vsrx-parity`

Evidence:

```go
// pkg/cli/cli_show_security_zones.go:196-205
if zpp.FromZone == name || zpp.ToZone == name {
    for _, pol := range zpp.Policies {
        if pol == nil {
            continue
        }
        fmt.Printf("    [zone-pair] %s -> %s: %s (%s)\n",
            zpp.FromZone, zpp.ToZone, pol.Name,
            policyActionStr(pol.Action))
```

```go
// pkg/grpcapi/server_show_zones_text.go:176-185
if zpp.FromZone == name || zpp.ToZone == name {
    for _, pol := range zpp.Policies {
        if pol == nil {
            continue
        }
        fmt.Fprintf(buf, "    [zone-pair] %s -> %s: %s (%s)\n",
            zpp.FromZone, zpp.ToZone, pol.Name, policyActionStr(pol.Action))
```

Contrast with the policy inventory:

```go
// pkg/api/types.go:206-220
// SchedulerName / Inactive expose the policy's scheduler binding and its
// runtime scheduler state...
SchedulerName string `json:"scheduler_name,omitempty"`
Inactive      bool   `json:"inactive,omitempty"`
```

Runtime trace:

1. A scheduled `permit` is currently inactive.
2. Runtime and match-policies skip it, falling through to a later rule/default deny.
3. `show security zones detail` prints `[zone-pair] trust -> untrust: scheduled-allow (permit)` with no scheduler or inactive marker.

Why it matters:

For a firewall audit, "policy exists in config" and "policy currently active in dataplane" are different facts. The summary claims to describe evaluation order, but it omits the scheduler state that can make the listed rule a non-participant.

Fix:

Thread the same scheduler active-state used by policy detail/inventory into the zone-detail summary. Render at least `scheduler-name` and `(inactive)` or skip inactive rules with a clear note. Add tests for inactive and active scheduled zone-pair and global policies.

### H04. REST global stats hide kernel host-inbound denies when the dataplane is unloaded

Severity: High
Confidence: High
Labels: `bug`, `observability`, `host-inbound`, `vsrx-parity`

Evidence:

```go
// pkg/api/stats.go:12-16
func (s *Server) globalStatsHandler(w http.ResponseWriter, _ *http.Request) {
    if s.dp == nil || !s.dp.IsLoaded() {
        writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
        return
    }
```

The Prometheus collector explicitly fixed this class:

```go
// pkg/api/metrics_counters.go:27-40
// The nft `inet xpf_hostinbound` chain is installed by the daemon INDEPENDENT of
// dataplane load state and keeps dropping control-plane traffic in a config-only
// / degraded boot, so Collect calls this BEFORE the dataplane gate...
func (c *xpfCollector) collectHostInboundKernelDenies(ch chan<- prometheus.Metric) {
```

Runtime trace:

1. Userspace dataplane is degraded or not loaded.
2. Kernel nft host-inbound chain is still installed and dropping traffic.
3. Prometheus exposes `xpf_host_inbound_kernel_denies_total`.
4. REST `/api/v1/statistics/global` returns 503 before reading the same counters.

Why it matters:

Operators using REST automation lose the primary host-inbound enforcement signal exactly during degraded boot, when management-plane exposure is most important to audit.

Fix:

Either split host-inbound kernel stats into a dataplane-independent REST endpoint or populate a partial global response with an explicit dataplane degraded flag. Do not gate kernel nft host-inbound counters on `dp.IsLoaded()`.

### H05. REST global stats turns nft host-inbound counter read errors into zero

Severity: High
Confidence: High
Labels: `bug`, `observability`, `host-inbound`

Evidence:

```go
// pkg/api/stats.go:57-66
// Best-effort: a netlink read failure leaves the field 0...
if kc, err := nftables.ReadHostInboundDenyCounters(); err == nil {
    for _, ctr := range kc {
        stats.HostInboundKernelDenies += ctr.Packets
    }
}
```

Prometheus deliberately does the opposite:

```go
// pkg/api/metrics_counters.go:34-44
// On a read failure the series is SKIPPED (no misleading 0) and
// xpf_counter_read_errors_total is bumped...
counts, err := readHostInboundDenyCounters()
if err != nil {
    c.counterReadErrors.Add(1)
    return
}
```

Runtime trace:

If netlink permission/state breaks, REST reports `"host_inbound_kernel_denies": 0`. That is indistinguishable from "kernel host-inbound is healthy and saw no denies."

Why it matters:

For a security appliance, "counter unavailable" and "zero denies" must not collapse. This is the exact contract already applied to userspace global counters and Prometheus kernel host-inbound counters.

Fix:

Return an error, add a separate `host_inbound_kernel_denies_available` boolean/error field, or make the REST endpoint mirror Prometheus semantics by omitting the field and surfacing a read error.

### H06. REST match-policies accepts signed `+80` ports after #3606 made ports canonical

Severity: High
Confidence: High
Labels: `bug`, `diagnostics`, `closed-issue-regression`, `vsrx-parity`

Evidence:

```go
// pkg/api/api.go:128-143
func queryIntStrict(r *http.Request, key string, def int) (int, bool) {
    v := r.URL.Query().Get(key)
    if v == "" {
        return def, true
    }
    n, err := strconv.Atoi(v)
    if err != nil || n < 0 {
        return 0, false
    }
```

The repo docs say numeric port tokens must be unsigned canonical decimals:

```md
<!-- docs/config-schema.md:295-319 -->
A numeric port token must be a plain unsigned decimal — no leading sign
(`+80` / `-80`), no surrounding whitespace...
The single parse authority is now `parseCanonicalPort`...
```

Runtime trace:

`GET /api/v1/security/match-policies?...&destination_port=+80` passes `strconv.Atoi("+80")`, so the simulator tests port 80. A config containing `+80` would not commit and the Rust parser now rejects signed ports.

Why it matters:

The diagnostic surface accepts packet selectors the config grammar and dataplane canonical parser reject. That can make automated policy verification green for a token family the platform no longer supports.

Fix:

Replace `queryIntStrict` for ports with a canonical decimal parser, or add a `queryPortStrict` using `strconv.ParseUint` plus a no-leading-sign/no-whitespace string check. Add REST tests for `+80`, whitespace, and normal `80`.

### H07. CLI match/test-policy port parser still accepts signed `+80`

Severity: High
Confidence: High
Labels: `bug`, `diagnostics`, `closed-issue-regression`, `vsrx-parity`

Evidence:

```go
// pkg/policymatch/policymatch.go:104-116
func ParsePort(s string) (int, error) {
    s = strings.TrimSpace(s)
    if s == "" {
        return 0, nil
    }
    n, err := strconv.Atoi(s)
```

Tests miss the signed-plus case:

```go
// pkg/policymatch/port_test.go:49-58
{"0", 0, false},
{"443", 443, false},
{"65535", 65535, false},
{"abc", 0, true},
{"70000", 0, true},
{"65536", 0, true},
{"-1", 0, true},
{"44a", 0, true},
```

Runtime trace:

`show security match-policies ... destination-port +80` and `request security test policy ... destination-port +80` parse as port 80. Rust and config now reject signed ports.

Why it matters:

This is a residual gap after #3606. It is not the original commit/runtime split, but the operator diagnostic still accepts the disallowed spelling and can produce a "matches permit" result for a non-canonical packet-selector token.

Fix:

Make `policymatch.ParsePort` enforce a bare run of ASCII digits, or expose/reuse `parseCanonicalPort` semantics in a package-safe way. Add tests for `+80` and surrounding whitespace if the CLI syntax should also reject whitespace for non-empty tokens.

### H08. ICMP type/code simulator parser accepts signed `+8`

Severity: Medium
Confidence: High
Labels: `bug`, `diagnostics`, `test-gap`

Evidence:

```go
// pkg/policymatch/policymatch.go:127-140
func ParseICMPValue(s string) (*uint8, error) {
    s = strings.TrimSpace(s)
    if s == "" {
        return nil, nil
    }
    n, err := strconv.Atoi(s)
```

Tests cover negative/out-of-range/malformed but not signed plus:

```go
// pkg/policymatch/icmp_test.go:177-190
if v, err := ParseICMPValue("0"); err != nil || v == nil || *v != 0 { ... }
if v, err := ParseICMPValue("255"); err != nil || v == nil || *v != 255 { ... }
if _, err := ParseICMPValue("256"); err == nil { ... }
if _, err := ParseICMPValue("-1"); err == nil { ... }
if _, err := ParseICMPValue("abc"); err == nil { ... }
```

Runtime trace:

`icmp-type +8` is accepted by the simulator as echo request. That is almost certainly not intended for Junos-like operator grammar and is inconsistent with the stricter port canonicality work.

Why it matters:

This is lower impact than ports because ICMP type/code are query selectors, not port policy leaves, but it is still a diagnostic grammar accepting non-canonical numeric tokens.

Fix:

Use the same `all ASCII digits` check before `Atoi`, and add plus-sign tests.

## Medium Confidence Findings

### M01. Remote `show security zones` still hides global/default policy tiers

Severity: Medium
Confidence: Medium
Labels: `feature-gap`, `remote-cli`, `security-observability`, `vsrx-parity`

Evidence:

```go
// cmd/cli/show.go:536-550
if polResp != nil {
    var refs []string
    for _, pi := range polResp.Policies {
        if pi.FromZone == z.Name || pi.ToZone == z.Name {
            dir := "from"
            peer := pi.ToZone
            ...
            refs = append(refs, fmt.Sprintf("%s %s (%d rules)", dir, peer, len(pi.Rules)))
        }
    }
```

Local/gRPC text were upgraded to all tiers:

```go
// pkg/cli/cli_show_security_zones.go:187-193
fmt.Println("  Policy summary (evaluation order: zone-pair, global, default-policy):")
zonePairPolicies := 0
for _, zpp := range cfg.Security.Policies {
```

Runtime trace:

Remote CLI gets `GetPolicies`, but then only lists zone-pair groups whose group-level `FromZone` or `ToZone` equals the zone. The global group is `*/*` and the synthetic default-policy group is `-/-`, so neither appears in the per-zone summary.

Why it matters:

Local `show security zones detail` and gRPC text now prevent global/default blindness, but remote CLI still presents the old incomplete model. Operators often use the remote ctl binary in production automation.

Fix:

Teach remote `showZones` the same tier renderer used by local/gRPC text, including per-rule global `MatchFromZone`/`MatchToZone` filtering and the synthetic default-policy row.

### M02. Remote filtered policy display renders all-zones global scope as `*`, not `any`

Severity: Medium
Confidence: Medium
Labels: `ux`, `remote-cli`, `vsrx-parity`

Evidence:

```go
// cmd/cli/show.go:584-597
if pi.FromZone == "*" && pi.ToZone == "*" {
    for _, rule := range pi.Rules {
        if !policymatch.GlobalPolicyAppliesToZonePair(...) {
            continue
        }
        gf, gt := "*", "*"
        if rule.MatchFromZone != "" {
            gf = rule.MatchFromZone
        }
```

Local renderers normalize empty global scope to `any`:

```go
// pkg/cli/cli_show_security_zones.go:219-222
fmt.Printf("    [global] %s -> %s: %s (%s)\n",
    globalZoneScopeLabel(gp.Match.FromZone),
    globalZoneScopeLabel(gp.Match.ToZone),
    gp.Name, policyActionStr(gp.Action))
```

Runtime trace:

An unscoped global policy shows as `From zone: *, To zone: *` remotely, while local/gRPC zone detail shows `any -> any`, and Junos syntax uses `any`.

Why it matters:

This is not an enforcement bug, but it makes remote output inconsistent and harder to map back to Junos-style config. It also makes `*` look like an internal wildcard instead of the explicit policy model.

Fix:

Use the same `matchScopeZone`/`globalZoneScopeLabel` style function in remote `showPoliciesFiltered`.

### M03. `request security test policy` omits policy ID/scope for global matches

Severity: Medium
Confidence: Medium
Labels: `diagnostics`, `security-observability`, `vsrx-parity`

Evidence:

```go
// pkg/cli/cli_request.go:324-328
if res.Global {
    fmt.Printf("Policy match (global):\n")
    fmt.Printf("  Policy:    %s\n", res.PolicyName)
    fmt.Printf("  Action:    %s\n", policymatch.ActionString(res.Action))
    return nil
}
```

The richer `show security match-policies` already includes ID and scope:

```go
// pkg/cli/cli_show_security.go:520-527
fmt.Printf("  From zone: %s, To zone: %s\n", fromZone, toZone)
fmt.Printf("  Policy: %s\n", res.PolicyName)
fmt.Printf("    Policy ID: %d\n", res.PolicyID)
if res.Global {
    fmt.Printf("    Scope: global (match from-zone: %s, to-zone: %s)\n",
```

Runtime trace:

If a global policy name is reused or a deny event/session table contains only `policy_id`, `request security test policy` cannot tell the operator which global runtime policy matched.

Why it matters:

vSRX-style troubleshooting expects policy-test output to be enough to reconcile with logs/session state. The older request command now lags the newer match-policies diagnostics.

Fix:

Render policy ID, global match scope, and description consistently in `request security test policy`.

### M04. gRPC text `test policy` has the same global-match identity gap

Severity: Medium
Confidence: Medium
Labels: `diagnostics`, `grpc-text`, `security-observability`

Evidence:

```go
// pkg/grpcapi/server_show_firewall.go:289-293
case res.Matched && res.Global:
    fmt.Fprintf(buf, "Policy match (global):\n")
    fmt.Fprintf(buf, "  Policy:    %s\n", res.PolicyName)
    fmt.Fprintf(buf, "  Action:    %s\n", policymatch.ActionString(res.Action))
case res.Matched:
```

Contrast:

```go
// proto/xpf/v1/xpf.proto:752-762
// policy_id is the stable runtime/RT_FLOW/session-table policy ID...
optional uint32 policy_id = 11;
```

Runtime trace:

The typed gRPC `MatchPoliciesResponse` has identity fields, but the gRPC text `test policy` path discards them for global matches.

Why it matters:

Text output is used by humans and possibly legacy scripts. It should not omit identity precisely for the global tier, where name collisions and broad scopes are common.

Fix:

Mirror local `show security match-policies` formatting in gRPC text `test policy`.

### M05. REST/gRPC match-policies response drops policy description

Severity: Medium
Confidence: Medium
Labels: `api-gap`, `diagnostics`, `vsrx-parity`

Evidence:

Core result carries the description:

```go
// pkg/policymatch/policymatch.go:326-331
PolicyName   string
Description  string
Action       config.PolicyAction
SrcAddresses []string
DstAddresses []string
Applications []string
```

The matched result fills it:

```go
// pkg/policymatch/policymatch.go:640-648
return Result{
    Matched:     true,
    Global:      global,
    ...
    PolicyName:  pol.Name,
    Description: pol.Description,
    Action:      pol.Action,
```

But REST drops it:

```go
// pkg/api/security.go:629-648
writeOK(w, MatchPoliciesResult{
    Matched:    true,
    PolicyName: res.PolicyName,
    Global:     res.Global,
    FromZone:   res.FromZone,
    ToZone:     res.ToZone,
    ...
    Applications: res.Applications,
})
```

Runtime trace:

Local CLI prints `Description` when present, but REST/gRPC match-policies consumers cannot retrieve it from the match response.

Why it matters:

Descriptions often carry ticket/change-control context. A match verdict without description is weaker than the policy inventory and local CLI result.

Fix:

Add `description` to REST `MatchPoliciesResult` and gRPC `MatchPoliciesResponse`, populate from `policymatch.Result.Description`, and add compatibility tests.

### M06. Match-policies response does not expose scheduler binding/effective state for matched scheduled policies

Severity: Medium
Confidence: Medium
Labels: `diagnostics`, `scheduler`, `security-observability`

Evidence:

Policy inventory exposes scheduler state:

```go
// pkg/api/types.go:206-220
SchedulerName string `json:"scheduler_name,omitempty"`
Inactive      bool   `json:"inactive,omitempty"`
```

The simulator skips inactive policies:

```go
// pkg/policymatch/policymatch.go:667-675
// scheduler gate, FIRST...
if q.PolicyInactiveFn != nil && q.PolicyInactiveFn(pol.SchedulerName) {
    return false
}
```

But match response has no scheduler fields:

```proto
// proto/xpf/v1/xpf.proto:718-731
message MatchPoliciesResponse {
  string policy_name = 1;
  string action = 2;
  repeated string src_addresses = 3;
  ...
```

Runtime trace:

When a scheduled policy is active and matches, the verdict says `permit` or `deny` but does not say it is controlled by scheduler `workhours`. When state later flips, the same query changes to default/next policy with little explanation in the single response.

Why it matters:

For audit parity, a policy-test answer should tell the operator not only which rule matched, but why it is active now and what time-gate controls it.

Fix:

Carry `scheduler_name` and an explicit `inactive=false`/`effective_state=active` on positive match responses. This mirrors policy inventory and avoids reverse lookups.

### M07. Match-policies cannot answer final host-inbound allow/deny

Severity: Medium
Confidence: Medium
Labels: `feature-gap`, `host-inbound`, `vsrx-parity`

Evidence:

Request shape has zones/IP/protocol/ports but no ingress interface, local interface/address, or host-inbound service token:

```proto
// proto/xpf/v1/xpf.proto:700-717
message MatchPoliciesRequest {
  string from_zone = 1;
  string to_zone = 2;
  string source_ip = 3;
  string destination_ip = 4;
  int32 destination_port = 5;
  string protocol = 6;
  int32 source_port = 7;
  optional uint32 icmp_type = 8;
```

The result explicitly punts:

```go
// pkg/policymatch/policymatch.go:289-301
// HostInboundUnmatched is true ONLY for a `to-zone junos-host` query...
// Local delivery is instead gated by host-inbound-traffic service admission...
// callers must render this as "host-inbound, subject to host-inbound-traffic..."
```

Runtime trace:

`match-policies from-zone trust to-zone junos-host protocol tcp destination-port 22` can tell you no host policy matched, but cannot determine whether `ssh` is allowed on the actual receiving interface/zone because it lacks the host-inbound service mapping input.

Why it matters:

The user explicitly wants vSRX core firewall behavior: packets denied when they should be denied and allowed when they should be allowed. Host-inbound is a core firewall decision, and the simulator cannot produce a final verdict for it.

Fix:

Add a dedicated host-inbound diagnostic request with ingress interface/local address/service/protocol token, or extend MatchPoliciesRequest with those fields and return `host_inbound_allowed` / `host_inbound_denied` with the matched source of admission.

### M08. Hardcoded host-inbound lifeline interfaces bypass zone host-inbound scoping without operator-visible policy

Severity: Medium
Confidence: Medium
Labels: `security-design`, `host-inbound`, `vsrx-parity`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:73-83
func hostInboundLifelineSet(cfg *config.Config) map[string]bool {
    set := map[string]bool{"fxp0": true}
    if cfg != nil && cfg.Chassis.Cluster != nil {
        cc := cfg.Chassis.Cluster
        for _, name := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
            if base := lifelineBaseName(name); base != "" {
                set[base] = true
```

```go
// pkg/dataplane/userspace/zones.go:94-102
func hostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
    base := lifelineBaseName(name)
    ...
    if lifelines[base] {
        return true
    }
    return base == "em0" || strings.HasPrefix(base, "fab")
}
```

```go
// pkg/dataplane/userspace/zones.go:236-240
for _, snap := range ifaceSnaps {
    if snap.Zone == "" || hostInboundLifelineInterface(snap.Name, lifelines) {
        continue
    }
```

Runtime trace:

Any interface with base `fxp0`, `em0`, or `fab*` is excluded from host-inbound deny scoping, even if an operator explicitly assigns it to a security zone in a standalone/lab/nonstandard config.

Why it matters:

The lifeline behavior is defensible for HA/management survivability, but it is an implicit policy exception. vSRX-style firewall posture should make management-plane exceptions explicit and visible.

Fix:

Surface lifeline exclusions in `show security zones detail` and API views, and consider making the bypass conditional on actual management/cluster role rather than base-name alone. At minimum, add a warning when a zoned interface is skipped by lifeline logic.

### M09. Reject replies build full response frames before rate-limit/budget gates

Severity: Medium
Confidence: Medium
Labels: `performance`, `dos-hardening`, `rust-dataplane`

Evidence:

```rust
// userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:243-258
let bytes = if meta.protocol == PROTO_TCP {
    build_reject_rst_frame(packet_frame)
} else {
    build_reject_icmp_unreachable(packet_frame, meta, ingress_ifindex, forwarding)
};
let Some(bytes) = bytes else { return false; };

if !syn_cookie_reply_budget_available(tx_pipeline) {
```

```rust
// userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:271-285
// per-reason token-bucket rate limit...
if !allow_generated_error(GeneratedErrorReason::Reject) {
```

Runtime trace:

Under a policy/filter `reject` flood with an empty rate bucket or exhausted TX budget, the dataplane still parses/builds the RST/ICMP frame first, then drops it.

Why it matters:

The comments call this a cold exception path, but reject floods are exactly a traffic class where CPU amplification matters. ICMP unreachable construction can require address/route/primary lookup before the packet is known to be rate-limited.

Fix:

Split cheap feasibility from full reply construction: do a minimal "reply could exist" parse first, apply rate/budget gates, then build bytes. Preserve the no-token-drain guarantee for unreplyable frames.

### M10. Policy and firewall-filter rejects still share one global rate bucket

Severity: Medium
Confidence: Medium
Labels: `performance`, `dos-hardening`, `rust-dataplane`, `vsrx-parity`

Evidence:

```rust
// userspace-dp/src/afxdp/icmp_ratelimit.rs:163-172
static TIME_EXCEEDED_BUCKET: TokenBucket = TokenBucket::new();
static PACKET_TOO_BIG_BUCKET: TokenBucket = TokenBucket::new();
static REJECT_BUCKET: TokenBucket = TokenBucket::new();

fn bucket_for(reason: GeneratedErrorReason) -> &'static TokenBucket {
    match reason {
        ...
        GeneratedErrorReason::Reject => &REJECT_BUCKET,
```

```rust
// userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:278-293
// policy and filter reject share this `Reject` bucket...
// Both sources still share the single global-per-reason REJECT_BUCKET;
// the aggregate `reject_rate_limited_total` ... stays source-NEUTRAL...
```

Runtime trace:

A firewall-filter `then reject` flood can consume/saturate the same `Reject` bucket used by security-policy `then reject`, causing policy reject replies to silently downgrade to drops. The per-source counters explain it after the fact but do not isolate it.

Why it matters:

Policy rejects and filter rejects can represent different operator intents and blast radii. A shared global bucket is simple, but not vSRX-grade fairness under adversarial traffic.

Fix:

Evaluate per-source or per-zone/per-binding reject buckets, with an aggregate cap for backscatter safety. Keep the current aggregate metric but enforce fairness before source-specific starvation.

### M11. Zone-detail policy summary omits policy IDs, so it cannot join to sessions/events

Severity: Medium
Confidence: Medium
Labels: `security-observability`, `diagnostics`

Evidence:

```go
// pkg/cli/cli_show_security_zones.go:203-205
fmt.Printf("    [zone-pair] %s -> %s: %s (%s)\n",
    zpp.FromZone, zpp.ToZone, pol.Name,
    policyActionStr(pol.Action))
```

```go
// pkg/api/types.go:192-205
// PolicyID / RuleID carry the runtime identity...
PolicyID uint32 `json:"policy_id"`
RuleID   string `json:"rule_id,omitempty"`
```

Runtime trace:

Zone detail tells the operator that a policy exists, but not the runtime `policy_id` seen in RT_FLOW/session/event telemetry.

Why it matters:

The summary is for zone-centric audit; without runtime identity, it cannot connect "this zone has this rule" to "this packet/event hit policy_id=N".

Fix:

Include policy ID and stable rule ID in the zone-detail policy summary, at least in detail mode.

### M12. Zone-detail policy summary omits log/count/exclusion modifiers

Severity: Medium
Confidence: Medium
Labels: `security-observability`, `feature-completeness`, `vsrx-parity`

Evidence:

Summary only prints action:

```go
// pkg/grpcapi/server_show_zones_text.go:183-185
fmt.Fprintf(buf, "    [zone-pair] %s -> %s: %s (%s)\n",
    zpp.FromZone, zpp.ToZone, pol.Name, policyActionStr(pol.Action))
```

Inventory has the richer semantics:

```go
// pkg/api/types.go:180-191
SourceAddressExcluded      bool `json:"source_address_excluded,omitempty"`
DestinationAddressExcluded bool `json:"destination_address_excluded,omitempty"`
LogSessionInit  bool `json:"log_session_init,omitempty"`
LogSessionClose bool `json:"log_session_close,omitempty"`
```

Runtime trace:

A rule with `source-address-excluded` or `then log session-init` renders the same as a plain rule in zone detail.

Why it matters:

For a firewall, inverted address matches and logging are part of the security intent. A zone summary can mislead by showing only `permit`/`deny`.

Fix:

Either mark the summary explicitly as "names/actions only" or include concise modifiers: `src-excluded`, `dst-excluded`, `log-init`, `log-close`, `count`.

### M13. Default-policy logging is not visible in zone-detail policy summary

Severity: Medium
Confidence: Medium
Labels: `security-observability`, `default-policy`, `vsrx-parity`

Evidence:

```go
// pkg/cli/cli_show_security_zones.go:228-233
// always surface the effective default-policy catch-all...
fmt.Printf("    [default] %s: %s\n",
    dataplane.DefaultPolicyName,
    policyActionStr(cfg.Security.DefaultPolicy))
```

The default row in REST inventory is a richer synthetic policy row:

```go
// pkg/api/security.go:333-346
// the IMPLICIT default-policy catch-all now has a reserved hit counter...
defRule := PolicyRule{
    Name: dataplane.DefaultPolicyName,
    Action: policyActionStr(cfg.Security.DefaultPolicy),
    ...
    PolicyID: dataplane.DefaultPolicySentinelID,
```

Runtime trace:

If default-policy logging is enabled, the zone detail still says only `[default] default-policy: deny` or `permit`, not whether unmatched traffic is logged.

Why it matters:

Default-policy behavior is often the last line of defense. Whether unmatched traffic is logged is operationally important during policy rollout.

Fix:

Append default-policy log posture to the default row, and include sentinel policy ID when in detail mode.

## Low Confidence / Triage Findings

### L01. `GlobalPolicyAppliesToZone` duplicates another wildcard helper instead of sharing semantics

Severity: Low
Confidence: High
Labels: `refactor`, `modularity`, `security-observability`

Evidence:

```go
// pkg/config/types_security.go:353-357
func GlobalPolicyAppliesToZone(m PolicyMatch, zone string) bool {
    asSource := m.FromZone == "" || m.FromZone == zone
    asDest := m.ToZone == "" || m.ToZone == zone
    return asSource || asDest
}
```

```go
// pkg/policymatch/policymatch.go:585-592
func GlobalPolicyAppliesToZonePair(matchFrom, matchTo, filterFrom, filterTo string) bool {
    axisApplies := func(scope, filter string) bool {
        if filter == "" || scope == "" || scope == "any" {
            return true
        }
```

Runtime trace:

The duplicated helper already drifted on explicit `any` (H01).

Why it matters:

Firewall scope semantics should have one Go source of truth outside the Rust runtime mirror.

Fix:

Move a small wildcard-axis helper into `pkg/config` or a neutral package and use it from both policy display and match-policies.

### L02. `policyActionStr`/action formatting is duplicated across API/CLI/gRPC

Severity: Low
Confidence: Medium
Labels: `refactor`, `modularity`

Evidence:

```go
// pkg/api/security.go:651-661
func policyActionStr(a config.PolicyAction) string {
    switch a {
    case config.PolicyPermit:
        return "permit"
    case config.PolicyDeny:
        return "deny"
    case config.PolicyReject:
```

Local CLI and gRPC text have parallel action formatting in their own packages.

Runtime trace:

Every display path must remember to update action names/modifiers separately when policy actions change.

Why it matters:

Action strings are security-facing. Drift creates audit mismatches that look like different policy behavior.

Fix:

Add a shared `config.PolicyAction.String()` or display helper and use it everywhere.

### L03. REST global stats aggregate kernel host-inbound denies across zones/families

Severity: Low
Confidence: Medium
Labels: `observability`, `host-inbound`

Evidence:

```go
// pkg/api/stats.go:62-65
if kc, err := nftables.ReadHostInboundDenyCounters(); err == nil {
    for _, ctr := range kc {
        stats.HostInboundKernelDenies += ctr.Packets
    }
}
```

Prometheus preserves labels:

```go
// pkg/api/metrics_descriptors.go:96-101
hostInboundKernelDenies: prometheus.NewDesc(
    "xpf_host_inbound_kernel_denies_total",
    ...
    []string{"zone", "family"}, nil,
)
```

Runtime trace:

REST can say there were 10,000 host-inbound denies, but not whether they were WAN IPv4, WAN IPv6, or an unexpected internal zone.

Why it matters:

For incident response, the zone/family split is often the signal. Aggregates hide source of exposure.

Fix:

Add a structured REST endpoint or nested field for per-zone/family host-inbound kernel denies.

### L04. Reject telemetry has source split but not policy/filter identity

Severity: Low
Confidence: Medium
Labels: `observability`, `rust-dataplane`

Evidence:

```go
// pkg/api/metrics_descriptors.go:1096-1106
userspaceRejectRateLimitedBySource: prometheus.NewDesc(
    "xpf_userspace_reject_rate_limited_by_source_total",
    ...
    []string{"source"}, nil,
)
```

```go
// pkg/api/metrics_userspace.go:81-88
emit := func(desc *prometheus.Desc, policy, filter uint64) {
    ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(policy), "policy")
    ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(filter), "filter")
}
```

Runtime trace:

The operator can tell policy rejects are rate-limited, but not which zone pair, policy ID, or firewall filter caused the pressure.

Why it matters:

This is not an enforcement bug, but it slows incident triage and tuning under reject floods.

Fix:

Consider low-cardinality dimensions: binding, direction, zone pair, or policy/filter ID, with cardinality guardrails.

### L05. Host-inbound lifeline omissions are not surfaced in rendered zone host-inbound views

Severity: Low
Confidence: Medium
Labels: `observability`, `host-inbound`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:236-245
for _, snap := range ifaceSnaps {
    if snap.Zone == "" || hostInboundLifelineInterface(snap.Name, lifelines) {
        continue
    }
    zone := cfg.Security.Zones[snap.Zone]
    if !configured(zone) {
        continue
```

Runtime trace:

A zone view will not list that an interface was excluded because it was a lifeline. It simply disappears from host-inbound address scoping.

Why it matters:

An operator auditing default-deny host-inbound behavior may not know an interface is intentionally outside that enforcement path.

Fix:

Render a "lifeline interfaces excluded from host-inbound deny" section for detail/API views.

### L06. No zone-detail tests for scheduler-inactive policy summaries

Severity: Low
Confidence: High
Labels: `test-gap`, `scheduler`, `security-observability`

Evidence:

Existing scheduler tests cover match-policies:

```go
// pkg/cli/cli_matchpolicies_scheduler_3414_test.go:71-84
// With NO scheduler-state provider... the simulator must treat
// the scheduler-bound permit as INACTIVE...
// makes the no-provider case below print the matched "Policy: night-allow"
```

Zone-detail tests cover global/default tiers but not schedulers:

```go
// pkg/cli/cli_show_security_zones_policy_tiers_3658_test.go:101-108
// fail-on-revert guard: a zone with only a global policy must show the global
// tier AND the effective default-policy catch-all...
```

Runtime trace:

The scheduler-awareness tests and zone-detail tier tests are in separate lanes, so H03 is unpinned.

Why it matters:

Zone-detail has become an audit surface; it needs the same scheduler fail-closed coverage as match-policies and inventory.

Fix:

Add scheduled active/inactive policy cases to local and gRPC zone-detail policy-tier tests.

### L07. No REST tests for dataplane-unloaded host-inbound kernel denies

Severity: Low
Confidence: High
Labels: `test-gap`, `host-inbound`, `observability`

Evidence:

Prometheus has the degraded-boot test:

```go
// pkg/api/metrics_host_inbound_kernel_test.go:12-21
// TestHostInboundKernelDeniesEmittedWhenDataplaneUnloaded...
func TestHostInboundKernelDeniesEmittedWhenDataplaneUnloaded(t *testing.T) {
```

REST has global counter tests, but the handler gates first:

```go
// pkg/api/stats.go:12-16
func (s *Server) globalStatsHandler(w http.ResponseWriter, _ *http.Request) {
    if s.dp == nil || !s.dp.IsLoaded() {
        writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
        return
```

Runtime trace:

The only explicit degraded-boot host-inbound deny test is Prometheus-specific; REST can stay blind.

Why it matters:

REST is a first-class API. Degraded host-inbound observability should be pinned on all supported management surfaces.

Fix:

Add REST tests for dp nil/unloaded plus mocked nft counters and netlink read error.

### L08. Numeric selector parser tests miss canonical-plus cases across REST/CLI

Severity: Low
Confidence: High
Labels: `test-gap`, `diagnostics`

Evidence:

Port test omits `+80`:

```go
// pkg/policymatch/port_test.go:49-58
{"0", 0, false},
{"443", 443, false},
...
{"-1", 0, true},
{"44a", 0, true},
```

REST parser has no visible canonicality test at the helper boundary:

```go
// pkg/api/api.go:134-143
func queryIntStrict(r *http.Request, key string, def int) (int, bool) {
    ...
    n, err := strconv.Atoi(v)
```

Runtime trace:

The tests prevent negative and malformed tokens but not `+80`, the exact class called out by #3606.

Why it matters:

This is how diagnostic grammar drifts from commit/runtime grammar again.

Fix:

Add table cases for `+80`, `+0`, ` 80`, and possibly Unicode digits if the intended grammar is ASCII-only.

### L09. Match-policies request cannot specify source interface/zone derivation context

Severity: Low
Confidence: Medium
Labels: `feature-gap`, `diagnostics`, `vsrx-parity`

Evidence:

```proto
// proto/xpf/v1/xpf.proto:700-709
message MatchPoliciesRequest {
  string from_zone = 1;
  string to_zone = 2;
  string source_ip = 3;
  string destination_ip = 4;
  int32 destination_port = 5;
  string protocol = 6;
  int32 source_port = 7;
```

Runtime trace:

The caller supplies zones directly. That is useful, but it cannot answer "which zone would this interface/packet actually resolve to?" or catch route/interface zone derivation mistakes.

Why it matters:

vSRX-style packet-trace diagnostics often start from ingress interface and destination. Pure zone-pair simulation misses routing/zone classification bugs.

Fix:

Add a packet-trace-style diagnostic that takes ingress interface plus packet tuple, resolves zones the same way the dataplane does, then runs policy.

### L10. Policy summary code is still a flat function, not a reusable firewall-audit module

Severity: Low
Confidence: Medium
Labels: `refactor`, `modularity`, `security-observability`

Evidence:

```go
// pkg/cli/cli_show_security_zones.go:178-187
// Policy detail breakdown...
fmt.Println("  Policy summary (evaluation order: zone-pair, global, default-policy):")
zonePairPolicies := 0
for _, zpp := range cfg.Security.Policies {
```

```go
// pkg/grpcapi/server_show_zones_text.go:160-168
// Policy detail breakdown...
buf.WriteString("  Policy summary (evaluation order: zone-pair, global, default-policy):\n")
zonePairPolicies := 0
```

Runtime trace:

Local and gRPC text each hand-roll policy-tier summaries. Remote CLI has a third, different renderer and is still incomplete.

Why it matters:

This is exactly the kind of modularity problem the audit prompt calls out: the module should be `security/policysummary/*.go`, not parallel feature-specific functions.

Fix:

Create a shared policy-audit model builder that returns tiered rows with IDs, scheduler, logging, inversion, default row, and rendered labels. Have local CLI, gRPC text, remote CLI, and tests consume it.

### L11. Reject path comment says source split, but old comment still says parse-error legs share policy counters

Severity: Low
Confidence: Medium
Labels: `docs`, `observability`, `rust-dataplane`

Evidence:

```rust
// userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:64-71
/// #2521: firewall-filter `then reject` now synthesizes the SAME active
/// reply as policy `reject`...
/// Budget, output-filter, and parse-error drops share policy reject's counters
/// and its fail-closed behavior...
```

Later code/comments split budget/output/rate by source:

```rust
// userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:260-267
// attribute the TX-frame-budget suppression to the reply's SOURCE...
match source {
    RejectReplySource::Policy => counters.policy_reject_reply_budget_drops += 1,
    RejectReplySource::Filter => counters.filter_reject_reply_budget_drops += 1,
}
```

Runtime trace:

The doc comment appears stale after #3615/#3657/#3661. If parse-error still lacks source split, the comment should be explicit; if not, it is misleading.

Why it matters:

Reject observability is already complex. Stale comments around source attribution can cause reviewers to miss real counter drift.

Fix:

Update the top-level comment to match current source-split behavior and explicitly name any remaining source-neutral legs.

### L12. Remote `show security zones` ignores GetPolicies failures silently

Severity: Low
Confidence: Medium
Labels: `observability`, `remote-cli`

Evidence:

```go
// cmd/cli/show.go:492-499
resp, err := c.client.GetZones(c.ctx(), &pb.GetZonesRequest{})
if err != nil {
    return fmt.Errorf("%v", err)
}

polResp, _ := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})
```

Runtime trace:

If zones load but policy inventory fails, remote `show security zones` prints zones without any warning that the policy portion is unavailable.

Why it matters:

This may have been flagged before in a broader remote-zone context, so I am marking it low-confidence for duplicate risk. It remains a real operator hazard: "no policies shown" can mean "policy RPC failed."

Fix:

Return the error in detail mode, or print a warning line per command output. Do not silently drop policy context.

## Suggested Issue Split

1. Fix explicit `any` handling and tests in `GlobalPolicyAppliesToZone`.
2. Add scheduler-aware and metadata-rich shared policy-tier summary builder for local CLI, gRPC text, and remote CLI.
3. Make REST `/statistics/global` host-inbound kernel counters dataplane-independent and error-aware.
4. Tighten match/test-policy numeric selector parsers to canonical unsigned decimal.
5. Extend match/test-policy diagnostics with policy description, scheduler binding, and host-inbound final-verdict capability.
6. Evaluate reject path fairness and pre-rate-limit CPU cost under adversarial reject floods.
7. Surface host-inbound lifeline bypasses explicitly.

## Duplicate Suppression Notes

I avoided re-reporting these prior topics except where a residual/new surface remains:

- Intrazone default permit/default-policy behavior and tests.
- Host-inbound configured/effective display already fixed by #3653/#3654/#3655.
- Reject reply ordering and source-split counters fixed by #3656/#3657/#3661.
- Signed port commit/runtime parser split fixed by #3606; this report only covers remaining simulator/REST query canonicality.
- Local/gRPC zone-detail global/default blindness fixed by #3658; this report covers explicit `any`, scheduler, metadata, and remote CLI residuals.
- Scheduler fail-open in match-policies fixed by #3414; this report covers missing scheduler metadata in policy-summary/match response surfaces.
