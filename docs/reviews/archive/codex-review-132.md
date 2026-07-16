# Codex review audit 132

## Run metadata

- Agent: codex
- Repo: `/home/ps/git/codex-bpfrx`
- Base commit: `6d3e109bc9f5`
- Sync: `git pull --rebase` returned `Already up to date.`
- Output number selection: `/tmp/agy-review-132.md` already exists, but `/tmp/codex-review-132.md` did not, so this run uses `132` as allowed by the audit instructions.
- Scope focus: firewall/vSRX core functionality, especially zone-policy diagnostics and host-inbound deny observability.

## Duplicate suppression

Read prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md`, especially:

- `/tmp/codex-review-131.md`: host-inbound bracket/flat-list tail drops, `then log` bracket tails, default-policy-log unknown-token behavior, `junos-host` log/policy-id visibility, nil zone snapshot admit-all, pre-id-default log parser, RuntimePolicyIDs gaps.
- `/tmp/agy-review-131.md`: conntrack GC race, static NAT rule shadowing, signed-port commit/apply split, dynamic-address feed leniency.
- `/tmp/codex-review-128.md`: unknown selector strictness, baseline addressless zone observability, ESP/AH global accept, ident-reset AF_XDP gap, per-interface host-inbound union, broad text-protocol parser duplication.
- Repo docs/logs read for issue suppression: `_Log.md`, `docs/feature-gaps.md`, `docs/host-inbound-service-matrix.md`.

I did not count those prior findings again. Several findings below are concrete remaining sub-cases in nearby code, with direct evidence and repros.

## Module checklist

| Module / feature | Inspected | Correctness/security | vSRX completeness | Perf/latency | Modularity | Tests |
|---|---:|---|---|---|---|---|
| `pkg/dataplane/userspace` host-inbound view/addressless detection | yes | New mixed-zone and per-family observability holes | Host-inbound default deny not fully observable per interface/family | Netlink recompute on scrape | addressless model is zone-scoped | missing mixed/family tests |
| `pkg/daemon` nft host-inbound apply/logging | yes | transition state keyed only by zone | interface churn hidden | low | logs depend on lossy model | missing churn tests |
| `pkg/api` Prometheus + REST match policies | yes | duplicate query params and no-config masking | operational diagnostics weaker than typed path | scrape recomputes netlink path | repeated query parsing | missing duplicate/no-config tests |
| `pkg/policymatch` selector parser | yes | duplicate selectors last-win | diagnostic CLI can test wrong packet | none | parser lacks presence map | missing duplicate tests |
| `cmd/cli` remote policy diagnostic | yes | delimiter-encoded topic cannot round-trip valid names | weaker than typed `show match-policies` | none | legacy text transport remains | no punctuation/duplicate tests |
| `pkg/grpcapi` `ShowText test-policy:` | yes | duplicate keys last-win | weaker than typed `MatchPolicies` RPC | none | hand parser duplicated | no duplicate/delimiter tests |
| `pkg/config` zone-name validation | yes | safe only for reserved tokens, not transport delimiters | Junos-style names need escaping or restriction | none | no central identifier codec | no transport round-trip canary |
| `userspace-dp/src/policy.rs` flow policy core | sampled | No new non-duplicate finding in the Rust match engine itself this pass; policy rule matching looked structurally sound in sampled paths | Prior broad parity gaps are already in docs | none from sample | large module remains a refactor target, but already broadly covered | not counted |

## Proof commands run

Temporary tests were added, run, and then removed before writing this report. The checkout was restored to clean.

- `go test ./pkg/policymatch -run TestCodexAuditDuplicateSelectorLastWins -count=1 -v` passed and proved duplicate CLI selectors are accepted with last value winning.
- `go test ./pkg/dataplane/userspace -run 'TestCodexAuditAddresslessDetectorMisses(MixedZone|SingleInterfaceOtherFamily)' -count=1 -v` passed and proved the addressless detector misses mixed-zone and single-family holes.
- `go test ./pkg/config -run TestCodexAuditZoneNamesMayContainTestPolicyDelimiters -count=1 -v` passed and proved comma/equal zone names commit.

## High confidence findings

### H01. Mixed-address zones hide addressless interfaces from host-inbound fail-open observability

- Severity: High
- Confidence: High
- Labels: `security`, `host-inbound`, `vsrx-parity`, `observability`, `bug`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:354-373
scoped := make(map[string]bool)
for _, v := range BuildZoneHostInboundViews(cfg) {
    if len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0 {
        scoped[v.Zone] = true
    }
}
...
for _, name := range names {
    if scoped[name] {
        continue
    }
```

Runtime trace:

1. Zone `trust` has `ge-0-0-0.0` with `192.0.2.1/24` and `ge-0-0-1.0` with no static/live address yet.
2. `BuildZoneHostInboundViews` emits a view for `trust` because `ge-0-0-0.0` has an address.
3. `AddresslessEnforcingZones` marks the whole zone scoped and never reports `ge-0-0-1.0`.
4. The daemon log and Prometheus gauge stay silent even though the second interface is in the documented transient host-inbound fail-open window.

Why it matters:

The enforcement surface is address/interface-specific, but the observability surface collapses to zone. A multi-interface zone can have one safe interface and one DHCP-pending interface, and operators will see no warning.

Fix direction:

Make addressless state per interface and family, not per zone. A zone should be considered fully scoped only when every non-lifeline interface/family that can receive host-bound traffic has a resolved address or an explicit exempt reason.

### H02. IPv4 presence hides IPv6 host-inbound addressless windows, and vice versa

- Severity: High
- Confidence: High
- Labels: `security`, `ipv6`, `host-inbound`, `vsrx-parity`, `bug`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:358-362
for _, v := range BuildZoneHostInboundViews(cfg) {
    if len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0 {
        scoped[v.Zone] = true
    }
}
```

Runtime trace:

1. An interface has a configured IPv4 address but no IPv6 address yet.
2. Host-inbound default-deny for IPv4 has a scoped nft address set.
3. The IPv6 side has no address to scope, so a future IPv6 address can enter the same fail-open window described in the comments.
4. Because `len(v.V4Addrs) > 0` is enough to mark the zone scoped, no warning or metric exposes the IPv6 gap.

Why it matters:

vSRX-style security policy must not let IPv4 readiness imply IPv6 readiness. Dual-stack edge deployments commonly bring families up at different times.

Fix direction:

Track addressless state as `{zone, interface, family}`. Export and log family-specific state and add tests where one family is present and the other is absent.

### H03. Local policy diagnostic selectors accept duplicates and silently use the last value

- Severity: Medium
- Confidence: High
- Labels: `policy-diagnostics`, `firewall`, `cli`, `bug`

Evidence:

```go
// pkg/policymatch/policymatch.go:365-453
for i := 0; i < len(args); i++ {
    switch args[i] {
    case "from-zone":
        v, err := takeValue(&i, "from-zone")
        ...
        s.FromZone = v
    ...
    case "protocol":
        ...
        s.Protocol = v
```

Runtime trace:

1. Operator runs `test security policy-match from-zone trust from-zone dmz to-zone untrust protocol tcp protocol udp`.
2. Parser accepts the vector.
3. `FromZone` becomes `dmz`; `Protocol` becomes `udp`.
4. The diagnostic verdict describes a different packet than the operator typed.

Why it matters:

This is a policy simulator used to prove allow/deny behavior. Last-win duplicate selectors can hide copy/paste mistakes and certify the wrong zone pair.

Fix direction:

Add a `seen map[string]struct{}` in `ParseSelectorArgs` and reject any duplicate selector, even if the duplicate value is identical. Add table tests for each duplicated selector.

### H04. gRPC `ShowText` `test-policy:` accepts duplicate keys and silently uses the last value

- Severity: Medium
- Confidence: High
- Labels: `grpc`, `policy-diagnostics`, `firewall`, `bug`

Evidence:

```go
// pkg/grpcapi/server_show_firewall.go:193-206
if params != "" {
    for _, kv := range strings.Split(params, ",") {
        parts := strings.SplitN(kv, "=", 2)
        ...
        switch parts[0] {
        case "from":
            fromZone = parts[1]
        case "to":
            toZone = parts[1]
```

Runtime trace:

1. A client sends `test-policy:from=trust,from=dmz,to=untrust,proto=tcp`.
2. The parser loops through both `from` keys.
3. `fromZone` is overwritten with `dmz`.
4. The response is a valid-looking policy verdict for the wrong source zone.

Why it matters:

This path is the remote CLI bridge and accepts raw text topics from clients. It fixed missing/unknown selectors but still lacks duplicate detection.

Fix direction:

Either route this through the shared selector parser after decoding to argv form, or add the same duplicate-key rejection before any field assignment.

### H05. Remote `test policy` cannot round-trip valid comma-bearing zone names

- Severity: Medium
- Confidence: High
- Labels: `policy-diagnostics`, `cli`, `grpc`, `vsrx-parity`, `bug`

Evidence:

```go
// cmd/cli/main.go:467-481
topic := fmt.Sprintf("test-policy:from=%s,to=%s", fromZone, toZone)
if srcIP != "" {
    topic += ",src=" + srcIP
}
...
if proto != "" {
    topic += ",proto=" + proto
}
```

```go
// pkg/grpcapi/server_show_firewall.go:193-198
for _, kv := range strings.Split(params, ",") {
    parts := strings.SplitN(kv, "=", 2)
    if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
        parseErr = fmt.Errorf("malformed selector segment %q", kv)
```

```go
// pkg/config/compiler_validate_strict.go:2557-2561
var reservedZoneNames = map[string]struct{}{
    "junos-global": {},
    "any":          {},
    "junos-host":   {},
}
```

Runtime trace:

1. Config accepts a zone named `trust,blue` because only exact reserved zone tokens are rejected.
2. Local parser can hold `from-zone trust,blue` in `SelectorArgs`.
3. Remote CLI serializes `test-policy:from=trust,blue,to=untrust`.
4. Server splits at the comma and treats `blue` as a malformed segment.

Why it matters:

Either punctuation-rich identifiers are supported or they are not. Right now config accepts names that at least one operational diagnostic cannot address remotely.

Fix direction:

Prefer removing the legacy text topic and using typed `MatchPoliciesRequest`. If text topics remain, introduce a central percent-encoding/decoding contract and test all identifier-bearing topics.

### H06. REST match-policy diagnostics accept duplicate query parameters with first-win semantics

- Severity: Medium
- Confidence: High
- Labels: `rest`, `policy-diagnostics`, `firewall`, `bug`

Evidence:

```go
// pkg/api/security.go:487-504
fromZone := r.URL.Query().Get("from_zone")
toZone := r.URL.Query().Get("to_zone")
...
srcIPStr := r.URL.Query().Get("src_ip")
```

```go
// pkg/api/api.go:142-148
func queryIntStrict(r *http.Request, key string, def int) (int, bool) {
    v := r.URL.Query().Get(key)
    if v == "" {
        return def, true
    }
```

Runtime trace:

1. A monitor calls `/api/v1/security/match-policies?from_zone=trust&from_zone=dmz&to_zone=untrust`.
2. `url.Values.Get` returns the first value, so REST tests `trust`.
3. CLI duplicate selectors currently use last-win behavior, so similar input there tests `dmz`.
4. Two policy diagnostics disagree without either returning a malformed-query error.

Why it matters:

Firewall policy diagnostics should fail closed on ambiguous inputs. Repeated HTTP query parameters are a normal ambiguity and should not silently select one interpretation.

Fix direction:

Add a helper that rejects `len(r.URL.Query()[key]) > 1` for every scalar selector before parsing values.

## Medium confidence findings

### M01. REST match-policies returns a 200 default-deny before validating malformed selectors when no config is active

- Severity: Medium
- Confidence: Medium
- Labels: `rest`, `policy-diagnostics`, `bug`

Evidence:

```go
// pkg/api/security.go:468-484
cfg := s.store.ActiveConfig()
if cfg == nil {
    nilRes := policymatch.Result{DefaultUsed: true, Action: config.PolicyDeny}
    writeOK(w, MatchPoliciesResult{
        Action: nilRes.DisplayAction(),
        DefaultUsed: true,
        QueriedFromZone: r.URL.Query().Get("from_zone"),
        QueriedToZone:   r.URL.Query().Get("to_zone"),
    })
    return
}
```

Runtime trace:

1. During startup or after config unload, a client sends a malformed diagnostic such as `dst_port=abc`.
2. Handler returns `200` default-deny before running `queryIntStrict`.
3. The same malformed input returns `400` once a config exists.

Why it matters:

The no-config fail-closed behavior is good for the verdict, but malformed selector grammar is still a client error. Returning success can hide broken monitoring or CI during the exact boot window where diagnostics are often polled.

Fix direction:

Validate request grammar before the `cfg == nil` verdict path. Then return default-deny only for syntactically valid requests with no active config.

### M02. Addressless transition logging is keyed only by zone, so interface churn while addressless is never logged

- Severity: Medium
- Confidence: Medium
- Labels: `host-inbound`, `observability`, `bug`

Evidence:

```go
// pkg/daemon/daemon_nft.go:288-303
func (d *Daemon) logHostInboundAddresslessTransitions(cfg *config.Config) {
    current := make(map[string]bool)
    for _, z := range dpuserspace.AddresslessEnforcingZones(cfg) {
        current[z.Zone] = true
        if !d.hostInboundAddresslessZones[z.Zone] {
            slog.Warn(... "zone", z.Zone, "interfaces", strings.Join(z.Interfaces, ","))
        }
    }
    ...
    d.hostInboundAddresslessZones = current
}
```

Runtime trace:

1. Zone `wan` enters addressless state on `ge-0-0-0.0`; daemon logs once.
2. Config changes: `ge-0-0-0.0` is fixed, but `ge-0-0-1.0` becomes addressless.
3. `current["wan"]` remains true across both applies.
4. No new warning is emitted, and the interface list in logs is stale.

Why it matters:

Operators need to know which link is in the host-inbound fail-open window. Zone-level dedupe hides materially different outages inside the same zone.

Fix direction:

Store state by stable key `{zone, interface, family}` or at least compare and log interface-set changes while a zone remains addressless.

### M03. `xpf_host_inbound_addressless_zones` lacks interface and family labels

- Severity: Medium
- Confidence: Medium
- Labels: `prometheus`, `host-inbound`, `observability`, `vsrx-parity`

Evidence:

```go
// pkg/api/metrics_descriptors.go:111-116
hostInboundAddresslessZones: prometheus.NewDesc(
    "xpf_host_inbound_addressless_zones",
    "1 while a configured host-inbound-enforcing zone has no resolvable "+
        "address yet ... labeled by zone.",
    []string{"zone"}, nil,
)
```

```go
// pkg/api/metrics_counters.go:70-72
for _, z := range dpuserspace.AddresslessEnforcingZones(cfg) {
    ch <- prometheus.MustNewConstMetric(c.hostInboundAddresslessZones,
        prometheus.GaugeValue, 1, z.Zone)
}
```

Runtime trace:

1. Alert fires for `zone="wan"`.
2. WAN zone has multiple units and dual-stack services.
3. The metric does not identify interface or family.
4. Operator must inspect config and live interface state out of band to find the affected traffic.

Why it matters:

For a security appliance, a fail-open signal should be actionable. Zone-only labels are too coarse once enforcement is actually interface/address/family scoped.

Fix direction:

Export per `{zone, interface, family}` series and keep a zone aggregate only as compatibility sugar.

### M04. Addressless detector tests miss mixed-zone and single-family cases

- Severity: Medium
- Confidence: Medium
- Labels: `tests`, `host-inbound`, `ipv6`

Evidence:

```go
// pkg/dataplane/userspace/zones_addressless_3698_test.go:54-66
got := AddresslessEnforcingZones(addresslessCfg3698())
if len(got) != 1 {
    t.Fatalf("AddresslessEnforcingZones = %+v, want exactly 1 (wan)", got)
}
if got[0].Zone != "wan" {
    t.Fatalf("reported zone = %q, want wan", got[0].Zone)
}
```

Runtime trace:

1. Existing fixture has one statically addressed zone and a different fully addressless zone.
2. It never puts an addressed interface and an addressless interface in the same zone.
3. It never checks one family scoped and the other family unscoped.
4. The zone-level bug in H01/H02 survives.

Why it matters:

The tests prove the first-order #3698 behavior but not the multi-interface/dual-stack behavior real firewalls use.

Fix direction:

Add regression tests for mixed interface state and v4-only/v6-only state, then refactor the detector to pass them.

### M05. `ShowText test-policy:` keeps a separate parser instead of using the shared selector contract

- Severity: Medium
- Confidence: Medium
- Labels: `modularity`, `policy-diagnostics`, `grpc`

Evidence:

```go
// pkg/grpcapi/server_show_firewall.go:174-202
func (s *Server) showTestPolicy(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
    params := strings.TrimPrefix(req.Topic, "test-policy:")
    var fromZone, toZone, srcIP, dstIP, proto string
    ...
    if params != "" {
        for _, kv := range strings.Split(params, ",") {
```

Runtime trace:

1. Strictness fixes land in `policymatch.ParseSelectorArgs`.
2. Server text topic must independently replicate every rule.
3. Duplicate-key and delimiter bugs remain only in the text parser.

Why it matters:

This is exactly the kind of duplicated boundary grammar that keeps producing policy-diagnostic false confidence.

Fix direction:

Retire the `ShowText test-policy:` grammar or translate it through one canonical typed request parser.

### M06. Remote `test policy` still uses `ShowText`, while `show security match-policies` already has a typed RPC

- Severity: Medium
- Confidence: Medium
- Labels: `cli`, `grpc`, `policy-diagnostics`, `modularity`

Evidence:

```go
// cmd/cli/show.go:1196-1214
req := &pb.MatchPoliciesRequest{
    FromZone:        sel.FromZone,
    ToZone:          sel.ToZone,
    SourceIp:        sel.SrcIP,
    DestinationIp:   sel.DstIP,
    Protocol:        sel.Protocol,
    SourcePort:      int32(sel.SrcPort),
    DestinationPort: int32(sel.DstPort),
}
...
resp, err := c.client.MatchPolicies(c.ctx(), req)
```

```go
// cmd/cli/main.go:467-489
topic := fmt.Sprintf("test-policy:from=%s,to=%s", fromZone, toZone)
...
return c.showText(topic)
```

Runtime trace:

1. `show security match-policies` sends typed fields over gRPC.
2. `test security policy-match` serializes the same selector concepts into a comma-delimited text topic.
3. The text path has duplicate and escaping bugs the typed path avoids.

Why it matters:

Both commands answer the same safety question: would this packet be allowed or denied? The weaker path should not remain as the operator-facing shortcut.

Fix direction:

Move `testPolicy` to `MatchPoliciesRequest` and delete the `test-policy:` `ShowText` branch after compatibility planning.

### M07. Prometheus collection recomputes netlink-backed host-inbound views on every scrape

- Severity: Medium
- Confidence: Medium
- Labels: `performance`, `prometheus`, `host-inbound`, `latency`

Evidence:

```go
// pkg/api/metrics_counters.go:66-72
cfg := c.srv.store.ActiveConfig()
...
for _, z := range dpuserspace.AddresslessEnforcingZones(cfg) {
    ch <- prometheus.MustNewConstMetric(...)
}
```

```go
// pkg/dataplane/userspace/zones.go:96-100
func BuildZoneHostInboundViews(cfg *config.Config) []ZoneHostInboundView {
    if cfg == nil || len(cfg.Security.Zones) == 0 {
        return nil
    }
    ifaceSnaps := buildInterfaceSnapshots(cfg)
```

```go
// pkg/dataplane/userspace/interfaces.go:437-442,511-516
if link, err := netlink.LinkByName(linuxName); err == nil && link != nil {
    ...
    addresses = buildInterfaceAddressSnapshots(link)
}
...
addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
```

Runtime trace:

1. Prometheus scrapes `/metrics`.
2. Collector calls `AddresslessEnforcingZones`.
3. That calls `BuildZoneHostInboundViews`.
4. That walks interfaces and calls netlink for addresses.

Why it matters:

Metrics scrapes should not perform repeated netlink walks proportional to interface count if the daemon already computes the same state during apply/lease-change. On larger appliances, scrape latency and netlink contention become avoidable control-plane noise.

Fix direction:

Cache addressless state in the daemon/config store when apply or interface address changes occur. Let the collector read the cached snapshot.

### M08. Zone-name grammar has no central transport-safety contract

- Severity: Medium
- Confidence: Medium
- Labels: `config`, `cli`, `grpc`, `modularity`, `vsrx-parity`

Evidence:

```go
// pkg/config/compiler_validate_strict.go:2525-2533
// reservedZoneNames is the set of tokens the dataplane / Junos grammar reserves
// for a special context and that therefore must NEVER be the name of an
// operator-defined `security zones security-zone <name>` (#3055).
...
var reservedZoneNames = map[string]struct{}{
```

Runtime trace:

1. Config validation protects special semantic tokens.
2. It does not define which identifier bytes can safely travel through text operational protocols.
3. At least one diagnostic transport uses `,` and `=` as unescaped delimiters.
4. Valid config identifiers can become unaddressable or ambiguous operationally.

Why it matters:

A router OS needs a single identifier contract. Either restrict the grammar or make every transport encode it.

Fix direction:

Create a shared identifier codec/test matrix covering zone, policy, address-book, application, interface, and routing-instance names across CLI, REST, gRPC, and display topics.

## Low confidence / triage findings

### L01. Host-inbound addressless logic should be moved into a dedicated package

- Severity: Low
- Confidence: Low
- Labels: `refactor`, `host-inbound`, `modularity`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:315-350
type AddresslessEnforcingZone struct {
    Zone string
    Interfaces []string
}
...
func AddresslessEnforcingZones(cfg *config.Config) []AddresslessEnforcingZone {
```

Why it matters:

The model is now consumed by dataplane view building, daemon logs, and Prometheus. Keeping it as a zone-only helper inside `userspace/zones.go` makes it easy for enforcement and observability to diverge.

Fix direction:

Move to something like `pkg/hostinbound/addressless/*.go` with explicit `{zone, interface, family, reason}` state.

### L02. Add selector fuzz/property tests for duplicates and escaping

- Severity: Low
- Confidence: Low
- Labels: `tests`, `policy-diagnostics`

Evidence:

```go
// pkg/policymatch/selector_args_3696_test.go:24-57
cases := []struct {
    name    string
    args    []string
    wantErr string
}{
    {"trailing from-zone", []string{"from-zone"}, "requires a value"},
    ...
    {"full valid", []string{...}, ""},
}
```

Why it matters:

The strictness table covers missing, empty, unknown, and malformed values but not duplicates or serialization round-trips.

Fix direction:

Add table cases plus fuzzing for `SelectorArgs -> transport -> server parser` equivalence.

### L03. REST scalar query helpers should reject repeated parameters generically

- Severity: Low
- Confidence: Low
- Labels: `rest`, `modularity`, `tests`

Evidence:

```go
// pkg/api/api.go:142-147
func queryIntStrict(r *http.Request, key string, def int) (int, bool) {
    v := r.URL.Query().Get(key)
    if v == "" {
        return def, true
    }
```

Why it matters:

Fixing only match-policies will leave the same first-win ambiguity in other scalar REST filters.

Fix direction:

Add `queryOne(r,key)` returning duplicate errors and route all scalar query parsers through it.

### L04. Add a transport round-trip canary for valid config identifiers

- Severity: Low
- Confidence: Low
- Labels: `tests`, `config`, `cli`, `grpc`, `vsrx-parity`

Evidence:

```go
// pkg/config/reserved_zone_name_3055_test.go:51-64
// TestOrdinaryZoneNameCommits asserts that ordinary zone names ...
"set security zones security-zone junos-global-edge",
"set security zones security-zone my-any-zone",
```

Why it matters:

Reserved-substring tests prove over-reject is avoided, but there is no opposite canary proving accepted identifiers work in operational commands.

Fix direction:

Create a list of accepted “nasty but valid” identifiers and verify CLI, REST, gRPC, and display surfaces can address them or reject them at commit.

### L05. Add DHCP/lease-arrival host-inbound smoke coverage for mixed-interface zones

- Severity: Low
- Confidence: Low
- Labels: `tests`, `host-inbound`, `dhcp`, `vsrx-parity`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:76-94
// re-rendered on every DHCP/DHCPv6 lease change ...
// ... transient fail-open admit window is surfaced to operators by
// AddresslessEnforcingZones (#3698)
```

Why it matters:

The comments describe the operational self-heal path, but the missed mixed-interface case needs a lease-change integration guard, not only unit tests.

Fix direction:

Smoke a zone with one static LAN unit and one DHCP WAN-style unit through address arrival/removal and assert nft payload plus metric/log state.

### L06. Keep a compatibility aggregate if adding per-interface Prometheus labels

- Severity: Low
- Confidence: Low
- Labels: `prometheus`, `compatibility`, `host-inbound`

Evidence:

```go
// pkg/api/metrics_descriptors.go:111-116
"xpf_host_inbound_addressless_zones",
...
[]string{"zone"}, nil,
```

Why it matters:

Operators may already alert on the zone-only metric. Fixing granularity should not silently remove the aggregate signal.

Fix direction:

Add `xpf_host_inbound_addressless_interfaces{zone,interface,family}` and keep the existing zone gauge as `max by(zone)`.

### L07. `test-policy:` text grammar should have a deprecation issue even if fixed in place

- Severity: Low
- Confidence: Low
- Labels: `grpc`, `cli`, `refactor`, `policy-diagnostics`

Evidence:

```go
// pkg/grpcapi/server_show_firewall.go:172-175
// --- #1700: residual ShowText branches ---
func (s *Server) showTestPolicy(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) ...
```

Why it matters:

The comment already calls it residual. Keeping it as a second-class policy diagnostic path keeps creating parity fixes.

Fix direction:

Open a follow-up to deprecate this topic and converge all policy simulation onto typed RPCs.

### L08. Policy diagnostic no-config semantics should be documented as verdict-only, not grammar-ok

- Severity: Low
- Confidence: Low
- Labels: `docs`, `rest`, `policy-diagnostics`

Evidence:

```go
// pkg/api/security.go:470-474
if cfg == nil {
    // #3375: no active config is the deterministic fail-closed default deny.
    nilRes := policymatch.Result{DefaultUsed: true, Action: config.PolicyDeny}
```

Why it matters:

If the intended behavior is “any request returns default deny while no config exists,” document that it bypasses selector validation. If not, fix M01.

Fix direction:

Clarify the contract in API docs/tests and align gRPC/REST/CLI behavior.

### L09. The policy selector contract lacks explicit presence metadata

- Severity: Low
- Confidence: Low
- Labels: `refactor`, `policy-diagnostics`

Evidence:

```go
// pkg/policymatch/policymatch.go:349-353
func ParseSelectorArgs(args []string) (SelectorArgs, error) {
    var s SelectorArgs
    // takeValue consumes the token following a value-taking selector...
```

Why it matters:

Zero values currently mean “not present.” That is okay for validated argv but makes duplicate/presence/explicit-empty handling live outside the returned type.

Fix direction:

Consider returning `SelectorArgs` plus a presence bitset, or making duplicate validation part of construction so raw structs are not ambiguous.

### L10. Host-inbound addressless state has no reason enum

- Severity: Low
- Confidence: Low
- Labels: `observability`, `host-inbound`, `modularity`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:325-332
type AddresslessEnforcingZone struct {
    Zone string
    // Interfaces are the non-lifeline interface refs assigned to the zone...
    Interfaces []string
}
```

Why it matters:

DHCP pending, VRRP backup before VIP install, absent kernel netdev, and intentionally unnumbered interface are operationally different. One string list cannot distinguish them.

Fix direction:

Add reason codes such as `no-live-link`, `no-address-family`, `dhcp-pending`, `vrrp-vip-pending`, `unnumbered-unsupported`.

### L11. The addressless metric reads active config directly, not the actual daemon apply snapshot

- Severity: Low
- Confidence: Low
- Labels: `observability`, `daemon`, `prometheus`

Evidence:

```go
// pkg/api/metrics_counters.go:62-70
func (c *xpfCollector) collectHostInboundAddresslessZones(ch chan<- prometheus.Metric) {
    if c.srv == nil || c.srv.store == nil {
        return
    }
    cfg := c.srv.store.ActiveConfig()
```

Why it matters:

The metric recomputes intended state from current config and live netlink. The daemon log is based on apply-time state. Under rapid config/address churn, the two can describe different instants.

Fix direction:

Publish daemon-owned applied host-inbound addressless state to the collector.

### L12. Add negative tests that punctuation-rich zone names either fail commit or work remotely

- Severity: Low
- Confidence: Low
- Labels: `tests`, `config`, `policy-diagnostics`, `vsrx-parity`

Evidence:

```go
// cmd/cli/main.go:467-469
topic := fmt.Sprintf("test-policy:from=%s,to=%s", fromZone, toZone)
if srcIP != "" {
    topic += ",src=" + srcIP
}
```

Why it matters:

The current system is in the unsafe middle: permissive config plus unescaped operations. Tests should force one coherent contract.

Fix direction:

Table-test names containing comma, equals, percent, slash, bracket, spaces if allowed, and Unicode if parser allows it.

### L13. Add a policy-diagnostic consistency test across local CLI, remote CLI, REST, and gRPC

- Severity: Low
- Confidence: Low
- Labels: `tests`, `policy-diagnostics`, `firewall`

Evidence:

```go
// cmd/cli/show.go:1174-1184
func (c *ctl) showMatchPolicies(args []string) error {
    sel, err := policymatch.ParseSelectorArgs(args)
```

```go
// pkg/api/security.go:487-504
fromZone := r.URL.Query().Get("from_zone")
...
srcIPStr := r.URL.Query().Get("src_ip")
```

Why it matters:

All surfaces are supposed to answer the same allow/deny question. Their boundary grammars currently differ enough that drift keeps reappearing.

Fix direction:

Create a shared fixture and assert equal verdict/errors for the same logical selector set.

### L14. `AddresslessEnforcingZones` comment overstates metric/log agreement

- Severity: Low
- Confidence: Low
- Labels: `docs`, `host-inbound`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:339-343
// read back from BuildZoneHostInboundViews itself — the exact same builder that
// drives the nft emission — so this observability signal can never disagree with
// what applyHostInboundFilter actually enforces
```

Why it matters:

The builder agreement is true only at zone granularity. Enforcement is address-set/family scoped, so H01/H02 show the comment is too broad.

Fix direction:

Tighten the comment after the model is made per-interface/family.

### L15. `AddresslessEnforcingZone.Interfaces` is documented as exact authored refs, but observability needs resolved Linux names too

- Severity: Low
- Confidence: Low
- Labels: `observability`, `host-inbound`, `operations`

Evidence:

```go
// pkg/dataplane/userspace/zones.go:327-332
// Interfaces are the non-lifeline interface refs assigned to the zone
// (exactly as authored under `security zones <z> interfaces <ref>`), sorted.
Interfaces []string
```

Why it matters:

Operators debugging nft/netlink paths need both Junos refs and Linux netdev/bind target names. Authored refs alone are less actionable during DHCP or VLAN binding failures.

Fix direction:

Expose both `interface_ref` and `linux_name`/`bind_name` in logs and metrics.

### L16. vSRX parity issue labels should be explicit on policy-diagnostic and host-inbound gaps

- Severity: Low
- Confidence: Low
- Labels: `vsrx-parity`, `process`

Evidence:

```text
Audit instruction: report that feature parity issues should be labeled as such in git.
```

Why it matters:

Several issues above are not just cleanup; they affect Junos/vSRX-like operator guarantees for firewall policy simulation and host-inbound default deny.

Fix direction:

When filing, label H01/H02/H05/M03/M08/L04/L12 as `vsrx-parity`.

## Negative results / not counted

- I sampled `userspace-dp/src/policy.rs` around the main rule evaluation path. The core rule matcher was not where the new bugs in this pass came from. The remaining issues found are at the Go control-plane/diagnostic/observability boundary.
- I did not re-count already-known gaps for `junos-host` log/policy-id visibility, bracket tail parsing, default-policy-log display, ESP/AH global accept, or broad vSRX feature matrix items from `docs/feature-gaps.md`.
- I did not call `gh`; duplicate suppression used prior `/tmp` reports and repo markdown/logs as instructed.

