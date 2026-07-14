# Codex Review Audit 123 - Core Firewall / vSRX Parity Quota Campaign

Base commit reviewed: `eab3587f2f1cb52e8357563deb7cba5060413e79`

Output path: `/tmp/codex-review-123.md`

Command state:

```text
$ git pull --rebase
Already up to date.
$ git rev-parse HEAD
eab3587f2f1cb52e8357563deb7cba5060413e79
```

## Duplicate Suppression Summary

Read prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` reports, then suppressed findings already covered there:

- `/tmp/codex-review-001.md`: host-originated `from-zone junos-host`, unknown/global host-inbound fail-open, VLAN override ifindex risk, output-filter active reject parity, host-inbound deny events/counter conflation, AppID overlap/perf/HA issues.
- `/tmp/codex-review-002.md`: ident-reset AF_XDP drop, IPsec host-inbound bypass, older reject-event truthfulness surfaces, source-split reject counters in their earlier form.
- `/tmp/codex-review-121.md`: intrazone default-permit runtime/simulator/counter drift.
- `/tmp/codex-review-122.md`: REST/gRPC `policy_id` zero omission, AppID nil guard, NAT-only app refs omitted, scheduler inventory fields, policy count summary, local match-policies usage/wording/query context, session protocol names, structured default-policy/gRPC scope design gaps.
- `/tmp/agy-review-001.md`, `/tmp/agy-review-002.md`, `/tmp/agy-review-121.md`: conntrack GC race, static NAT overwrite/shadowing, signed port validation, dynamic-feed slash/empty bypass.

Relevant repo docs read for drift suppression included `README.md`, `docs/feature-gaps.md`, `docs/issues/pr-history.md`, `docs/issues/issue-history.md`, `pkg/api/README.md`, `pkg/grpcapi/README.md`, and `docs/junos-cli-reference.md`.

## Module Checklist

Inspected named modules/features:

1. REST zone inventory: `pkg/api/security.go`, `pkg/api/types.go`, `pkg/api/security_zone_hostinbound_3328_test.go`.
2. gRPC structured zone inventory: `pkg/grpcapi/server_show_zones.go`, generated proto comments, `proto/xpf/v1/xpf.proto`, tests.
3. Local CLI zone display: `pkg/cli/cli_show_security_zones.go`.
4. Local CLI interface display: `pkg/cli/cli_show_interfaces.go`.
5. Local CLI diagnostic command: `pkg/cli/cli_request.go`.
6. gRPC text zone/interface display: `pkg/grpcapi/server_show_zones_text.go`.
7. Remote gRPC CLI: `cmd/cli/show.go`.
8. Userspace host-inbound compile/enforcement: `pkg/dataplane/userspace/zones.go`, `userspace-dp/src/afxdp/forwarding/host_inbound.rs`.
9. Userspace reject reply path: `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`.
10. Userspace generated-error token buckets: `userspace-dp/src/afxdp/icmp_ratelimit.rs`.
11. Userspace status formatter: `pkg/dataplane/userspace/format/status.go`.
12. Prometheus userspace metrics: `pkg/api/metrics_descriptors.go`, `pkg/api/metrics_userspace.go`, `pkg/api/metrics_test.go`.
13. Policy inventory details: `pkg/api/security.go`, `pkg/cli/cli_show_security_zones.go`, `pkg/grpcapi/README.md`.
14. Text/doc surfaces: `pkg/api/README.md`, `pkg/grpcapi/README.md`, `docs/junos-cli-reference.md`.

Negative results:

- Runtime host-inbound dataplane enforcement for configured zones appears intentionally default-deny on the Rust userspace path; I did not find a fresh allow/deny bypass beyond older unknown/global-zone and VLAN-ifindex findings already reported.
- REST/gRPC structured inventory now does carry per-interface override rows; the fresh issue is the top-level configured bit/docs/tests still encode the old no-stanza admit-all distinction.
- Local `pkg/policymatch` host-inbound wording and queried-zone context appear fixed on master; the remaining stale wording is in the remote `cmd/cli` client.
- AppID nil guard and policy inventory scheduler omissions from audit 122 appear addressed; I did not duplicate them.

HPC/low-level invariants checked in this pass:

- Reject rate-limiting uses static per-reason token buckets; no endianness issue found in the inspected snippets, but the single shared `REJECT_BUCKET` creates behavioral coupling between policy and filter reject paths.
- Reject feasibility is checked after the shared token bucket is consumed; this is a low-level ordering bug under flood conditions because unreplyable frames still mutate global rate-limit state.
- The findings below focus on control-plane truthfulness, fail-closed semantics, and operator/debug visibility for a router/firewall appliance.

## Module-by-Module Inspection Log

### REST/gRPC Zone Inventory

Correctness/security: found stale no-stanza admit-all semantics in top-level `host_inbound_configured` even though dataplane now marks every configured zone enforcing.  
Feature completeness vs vSRX: vSRX-style default deny for configured zones is present in dataplane but not faithfully represented in APIs.  
Performance/latency: no hot-path issue; inventory construction is config-time/read-time only.  
Modularity/refactor: `host_inbound_configured` semantics are duplicated in REST, gRPC, proto comments, generated comments, READMEs, and tests.  
Test coverage: current tests assert the old no-stanza admit-all posture and would block a correct update.

### Local CLI Zone/Interface/Diagnostic Views

Correctness/security: per-interface host-inbound overrides are not rendered on multiple operator paths, so an interface can be governed by a narrower/wider effective set than the CLI shows.  
Feature completeness vs vSRX: incomplete `show security zones` / `show interfaces` parity for per-interface host-inbound.  
Performance/latency: no hot-path issue.  
Modularity/refactor: zone host-inbound rendering is ad hoc in several files rather than a shared presenter.  
Test coverage: no CLI tests exercise per-interface host-inbound rendering.

### gRPC Text and Remote CLI Views

Correctness/security: remote and text views drop fields carried by structured proto, including per-interface host-inbound and the configured posture bit.  
Feature completeness vs vSRX: incomplete operational parity for management-plane admission audit.  
Performance/latency: no hot-path issue.  
Modularity/refactor: structured and text renderers drift because no shared zone display model exists.  
Test coverage: structured gRPC tests exist, but text/remote client coverage does not check these fields.

### Rust Reject Reply Path

Correctness/security: reject token bucket is consumed before confirming a reply can be built; unreplyable frames can drain the budget.  
Feature completeness vs vSRX: policy/filter `reject` is active on input/lo0, but source-specific observability and fairness remain incomplete.  
Performance/latency: shared global bucket can induce cross-feature head-of-line behavior during floods.  
Modularity/refactor: source-specific counters exist, but source-specific rate-limit state does not.  
Test coverage: no tests for unreplyable frames consuming reject tokens or source starvation.

### Userspace Status and Prometheus Metrics

Correctness/security: helper tracks successful policy/filter reject replies and budget drops, but key operator surfaces omit them.  
Feature completeness vs vSRX: weaker than SRX-style reject/action troubleshooting.  
Performance/latency: metrics emission is read path; no hot-path issue.  
Modularity/refactor: wire counters, status formatter, docs, and Prometheus descriptors are not generated from a shared counter inventory.  
Test coverage: tests cover only aggregate reject rate-limited metric, not sent/budget/source split counters.

## High Confidence Findings

### H01. REST and gRPC `host_inbound_configured` still report old no-stanza admit-all semantics after the dataplane changed configured zones to default-deny

Severity: High  
Confidence: High

Evidence:

`pkg/api/security.go:57-68`

```go
57		// HostInboundConfigured mirrors ZoneSnapshot.HostInboundConfigured
58		// (#3070/#3362): the zone is host-inbound ENFORCING when it declares a
59		// zone-level stanza OR carries any per-interface override.
60		zi.HostInboundConfigured = zone.HostInboundTraffic != nil || len(zone.InterfaceHostInbound) > 0
61		for _, ref := range zone.SortedInterfaceHostInboundRefs() {
62			hib := zone.InterfaceHostInbound[ref]
63			zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, ZoneInterfaceHostInbound{
64				Interface:      ref,
65				Configured:     true,
66				SystemServices: append([]string{}, hib.SystemServices...),
67				Protocols:      append([]string{}, hib.Protocols...),
68			})
```

`pkg/grpcapi/server_show_zones.go:55-66`

```go
55		// host_inbound_configured mirrors ZoneSnapshot.HostInboundConfigured
56		// (#3070/#3362): the zone is host-inbound ENFORCING when it declares a
57		// zone-level stanza OR carries any per-interface override.
58		zi.HostInboundConfigured = zone.HostInboundTraffic != nil || len(zone.InterfaceHostInbound) > 0
59		for _, ref := range zone.SortedInterfaceHostInboundRefs() {
60			hib := zone.InterfaceHostInbound[ref]
61			zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, &pb.InterfaceHostInbound{
62				Interface:      ref,
63				Configured:     true,
64				SystemServices: append([]string{}, hib.SystemServices...),
65				Protocols:      append([]string{}, hib.Protocols...),
66			})
```

Actual dataplane compile/enforcement now says every configured zone is enforcing:

`pkg/dataplane/userspace/zones.go:475-496`

```go
475		// #3405: EVERY configured security zone is host-inbound-ENFORCING (Junos
476		// default-deny parity). A zone with NO `host-inbound-traffic` stanza
477		// carries HostInboundConfigured=true with EMPTY token sets, so the Rust
478		// classifier inserts it into `zone_host_inbound` with an empty
479		// `ZoneHostInbound` -> `admits()` returns false for every
480		// service/protocol -> default-deny, identical to an empty
481		// `host-inbound-traffic { }` stanza and to the kernel-nft catch-all DROP
482		// (BuildZoneHostInboundViews). Before #3405 a no-stanza zone stayed
483		// unconfigured (absent from the table -> `None => true` admit-all), a
484		// permit-all management-plane exposure on any zone the operator never
485		// locked down. The global ICMP/ND/PMTUD accepts (#3171) still precede the
486		// per-zone deny on the Rust path, and lifeline interfaces (fxp0/em0/fab*)
487		// never reach the AF_XDP local-delivery classifier, so the flip cannot
488		// strand management or break HA.
489		//
490		// #3362: the zone-keyed set stays the zone-level set (possibly EMPTY ->
491		// fail-closed deny-all for any interface in the zone WITHOUT an override),
492		// and overridden interfaces are admitted via the per-interface ifindex map
493		// (InterfaceSnapshot.HostInbound*).
494		if zone := cfg.Security.Zones[name]; zone != nil {
495			zs.HostInboundConfigured = true
496			if zone.HostInboundTraffic != nil {
```

Runtime trace:

1. Operator configures `security-zone untrust` with interfaces but no `host-inbound-traffic` stanza.
2. Userspace compiler sets `ZoneSnapshot.HostInboundConfigured=true` and empty token sets for that configured zone.
3. Rust classifier inserts an empty admission set; `admits()` returns false for every service/protocol, so SSH/SNMP/BGP host-bound traffic is denied by default.
4. REST/gRPC structured inventory computes `host_inbound_configured=false` because no zone-level stanza and no interface override exist.
5. Automation reads the API and concludes the old no-stanza admit-all posture, contradicting runtime enforcement.

Why it matters:

This is a core firewall posture truthfulness bug. Controllers and auditors need to know whether management-plane traffic is open or fail-closed. Current structured APIs report the opposite posture for no-stanza configured zones.

Suggested fix direction:

Use the same semantic as `ZoneSnapshot`: every configured zone should report host-inbound enforcing. Preserve an additional explicit field if the UI needs to distinguish configured stanza source, e.g. `host_inbound_source = none|zone|interface|zone+interface`, but do not overload the enforcement bit.

Suggested labels: `bug`, `host-inbound`, `api`, `grpc`, `security`, `vsrx-parity`

### H02. API/proto comments still document no-stanza as admit-all even though configured zones are default-deny

Severity: High  
Confidence: High

Evidence:

`pkg/api/types.go:90-97`

```go
90	// HostInboundConfigured (#3328) records whether the zone is host-inbound
91	// ENFORCING: true when the zone declares a `host-inbound-traffic` stanza OR
92	// carries any per-interface override (#3362). Mirrors the dataplane posture
93	// bit (ZoneSnapshot.HostInboundConfigured): false = no stanza = default
94	// admit-all for host-bound traffic; true with EMPTY service/protocol lists
95	// = explicit deny-all. Without it an operator cannot distinguish "no
96	// stanza" (admit-all) from "empty stanza" (deny-all).
97	HostInboundConfigured bool `json:"host_inbound_configured"`
```

`proto/xpf/v1/xpf.proto:230-237`

```proto
230	  // host_inbound_configured (#3328) records whether the zone is host-inbound
231	  // ENFORCING: true when the zone declares a `host-inbound-traffic` stanza OR
232	  // carries any per-interface override (#3362). This is the dataplane posture
233	  // bit (ZoneSnapshot.HostInboundConfigured): false = no stanza = default
234	  // admit-all for host-bound traffic; true with EMPTY lists = explicit
235	  // deny-all. Without it an operator cannot distinguish "no stanza"
236	  // (admit-all) from "empty stanza" (deny-all).
237	  bool host_inbound_configured = 12;
```

Runtime trace:

1. A generated client reads the proto comments or generated code and treats `false` as no-stanza admit-all.
2. The server also currently emits `false` for no-stanza configured zones.
3. The userspace dataplane denies host-bound traffic by default for that zone.
4. Operator docs and generated client semantics disagree with the security decision.

Why it matters:

Generated API comments become SDK documentation. This creates persistent cross-version drift even after the server code is fixed.

Suggested fix direction:

Update proto, generated docs, REST types comments, and regenerate gRPC code. Define `host_inbound_configured` as runtime enforcement only, and add a separate source/state enum if needed.

Suggested labels: `docs-drift`, `api`, `grpc`, `host-inbound`, `vsrx-parity`

### H03. REST and gRPC tests still assert the old no-stanza admit-all contract

Severity: High  
Confidence: High

Evidence:

`pkg/api/security_zone_hostinbound_3328_test.go:139-147`

```go
139		// open: no stanza at all = admit-all. configured MUST be false so it is
140		// distinguishable from locked.
141		open, ok := byName["open"]
142		if !ok {
143			t.Fatalf("open zone missing from REST inventory")
144		}
145		if open.HostInboundConfigured {
146			t.Fatalf("open host_inbound_configured = true, want false (no stanza = admit-all; #3328 must not collapse with the empty-stanza deny-all posture)")
147		}
```

`pkg/grpcapi/server_show_zones_hostinbound_3328_test.go:109-115`

```go
109	open, ok := byName["open"]
110	if !ok {
111		t.Fatal("open zone missing")
112	}
113	if open.GetHostInboundConfigured() {
114		t.Fatal("open host_inbound_configured = true, want false (no stanza = admit-all; #3328 must not collapse with the empty-stanza deny-all posture)")
115	}
```

Runtime trace:

1. Developer fixes H01 by reporting `host_inbound_configured=true` for every configured zone.
2. Existing REST/gRPC tests fail because they explicitly encode `no stanza = admit-all`.
3. The test suite pushes future edits back toward a stale security contract.

Why it matters:

Tests are now guarding the wrong invariant. This is especially risky for firewall default-deny behavior because future cleanup can accidentally reintroduce the pre-#3405 exposure.

Suggested fix direction:

Rewrite the tests around four distinct concepts: zone exists, enforcement posture, zone-level token set, and per-interface effective override. Add an explicit no-stanza default-deny test tied to #3405.

Suggested labels: `test-gap`, `host-inbound`, `api`, `grpc`, `security`

### H04. Local `show security zones` hides per-interface host-inbound overrides

Severity: High  
Confidence: High

Evidence:

`pkg/cli/cli_show_security_zones.go:58-72`

```go
58		fmt.Printf("  Interfaces bound: %d\n", len(zone.Interfaces))
59		fmt.Printf("  Interfaces:\n")
60		for _, ifName := range zone.Interfaces {
61			fmt.Printf("    %s\n", ifName)
62		}
63		if zone.HostInboundTraffic != nil {
64			if len(zone.HostInboundTraffic.SystemServices) > 0 {
65				fmt.Printf("  Allowed host-inbound traffic: %s\n",
66					strings.Join(zone.HostInboundTraffic.SystemServices, " "))
67			}
68			if len(zone.HostInboundTraffic.Protocols) > 0 {
69				fmt.Printf("  Allowed host-inbound protocols: %s\n",
70					strings.Join(zone.HostInboundTraffic.Protocols, " "))
71			}
72		}
```

`pkg/cli/cli_show_security_zones.go:107-124`

```go
107			if len(zone.Interfaces) > 0 {
108				fmt.Println("  Interface details:")
109				for _, ifName := range zone.Interfaces {
110					fmt.Printf("    %s:\n", ifName)
111					if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok {
112						for _, unit := range ifc.Units {
113							for _, addr := range unit.Addresses {
114								fmt.Printf("      Address: %s\n", addr)
115							}
116							if unit.DHCP {
117								fmt.Printf("      DHCPv4: enabled\n")
118							}
119							if unit.DHCPv6 {
120								fmt.Printf("      DHCPv6: enabled\n")
121							}
122						}
123					}
124				}
```

Runtime trace:

1. Zone `edge` has zone-level `host-inbound-traffic { system-services ping; }`.
2. Interface `reth0.50` has per-interface override/effective set adding `ssh`.
3. Dataplane admits SSH on `reth0.50` but not on another interface in the same zone.
4. `show security zones detail` prints interface addresses/DHCP and zone-level host-inbound only; it never prints the interface override.
5. Operator auditing SSH exposure cannot see the interface-specific allow.

Why it matters:

Per-interface host-inbound is a vSRX-style management-plane control. Hiding it on the primary local zone command makes deny/allow investigations incomplete.

Suggested fix direction:

Render `InterfaceHostInbound` under each interface in detail mode and summarize override count in non-detail mode. Use the same sorted ref helper as REST/gRPC.

Suggested labels: `bug`, `cli`, `host-inbound`, `observability`, `vsrx-parity`

### H05. Local `show interfaces` hides per-interface host-inbound overrides

Severity: High  
Confidence: High

Evidence:

`pkg/cli/cli_show_interfaces.go:299-312`

```go
299			fmt.Printf("    Security: Zone: %s\n", li.zoneName)
300	
301			// Host-inbound traffic services
302			if li.zone != nil && li.zone.HostInboundTraffic != nil {
303				hit := li.zone.HostInboundTraffic
304				if len(hit.SystemServices) > 0 {
305					fmt.Printf("    Allowed host-inbound traffic : %s\n",
306						strings.Join(hit.SystemServices, " "))
307				}
308				if len(hit.Protocols) > 0 {
309					fmt.Printf("    Allowed host-inbound protocols: %s\n",
310						strings.Join(hit.Protocols, " "))
311				}
312			}
```

Runtime trace:

1. Interface `ge-0/0/0.100` carries a per-interface host-inbound override.
2. Dataplane chooses interface-effective host-inbound first, then zone fallback.
3. Operator runs `show interfaces ge-0/0/0.100` to inspect interface posture.
4. CLI prints only zone-level host-inbound tokens, so it can show a deny where runtime allows or show an allow inherited from zone while missing a narrower override.

Why it matters:

Interface-centric audits are the natural place to verify per-interface management access. This output can mislead remediation during an incident.

Suggested fix direction:

Add per-interface effective host-inbound fields to the `logicalInterface` view model and render source (`zone`, `interface override`, `zone+interface effective`) explicitly.

Suggested labels: `bug`, `cli`, `host-inbound`, `vsrx-parity`

### H06. Local `test security-zone interface` omits the per-interface host-inbound override it is supposed to diagnose

Severity: High  
Confidence: High

Evidence:

`pkg/cli/cli_request.go:461-481`

```go
461	for zoneName, zone := range cfg.Security.Zones {
462		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
463			continue
464		}
465		for _, iface := range zone.Interfaces {
466			if iface == ifName {
467				fmt.Printf("Interface %s belongs to zone: %s\n", ifName, zoneName)
468				if zone.Description != "" {
469					fmt.Printf("  Description: %s\n", zone.Description)
470				}
471				if zone.ScreenProfile != "" {
472					fmt.Printf("  Screen:      %s\n", zone.ScreenProfile)
473				}
474				if zone.HostInboundTraffic != nil {
475					if len(zone.HostInboundTraffic.SystemServices) > 0 {
476						fmt.Printf("  Host-inbound services: %s\n", strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
477					}
478					if len(zone.HostInboundTraffic.Protocols) > 0 {
479						fmt.Printf("  Host-inbound protocols: %s\n", strings.Join(zone.HostInboundTraffic.Protocols, ", "))
480					}
481				}
```

Runtime trace:

1. Operator uses `test security-zone interface reth0.50` while debugging why SSH is allowed/denied.
2. Command finds the zone and prints screen plus zone-level host-inbound.
3. Runtime host-inbound path actually uses per-interface effective set for `reth0.50`.
4. Diagnostic command omits the decisive rule.

Why it matters:

This command is explicitly diagnostic. Returning partial admission state is worse than a neutral inventory gap because it can send the operator to the wrong config stanza.

Suggested fix direction:

When the selected interface has `zone.InterfaceHostInbound[ifName]`, print both zone-level and effective per-interface sets.

Suggested labels: `bug`, `cli`, `diagnostics`, `host-inbound`, `vsrx-parity`

### H07. gRPC text `show security zones` hides per-interface host-inbound overrides

Severity: High  
Confidence: High

Evidence:

`pkg/grpcapi/server_show_zones_text.go:63-72`

```go
63		if zone.HostInboundTraffic != nil {
64			if len(zone.HostInboundTraffic.SystemServices) > 0 {
65				fmt.Fprintf(buf, "  Host-inbound system-services: %s\n",
66					strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
67			}
68			if len(zone.HostInboundTraffic.Protocols) > 0 {
69				fmt.Fprintf(buf, "  Host-inbound protocols: %s\n",
70					strings.Join(zone.HostInboundTraffic.Protocols, ", "))
71			}
72		}
```

Runtime trace:

1. A remote CLI/text consumer uses gRPC text `show security zones` rather than structured `GetZones`.
2. Structured gRPC would include `interface_host_inbound`; text renderer uses only zone-level `HostInboundTraffic`.
3. Interface-specific host admission is absent from the operator output.

Why it matters:

A firewall can have correct enforcement and still be operationally unsafe if its standard text view hides exceptions. This is a vSRX parity gap for management-plane audit output.

Suggested fix direction:

Share a zone rendering helper between local CLI and gRPC text, and include per-interface overrides in detail output.

Suggested labels: `bug`, `grpc`, `text-cli`, `host-inbound`, `vsrx-parity`

### H08. gRPC text interface diagnostic hides per-interface host-inbound overrides

Severity: High  
Confidence: High

Evidence:

`pkg/grpcapi/server_show_zones_text.go:219-233`

```go
219					fmt.Fprintf(buf, "Interface %s belongs to zone: %s\n", ifName, zoneName)
220					if zone.Description != "" {
221						fmt.Fprintf(buf, "  Description: %s\n", zone.Description)
222					}
223					if zone.ScreenProfile != "" {
224						fmt.Fprintf(buf, "  Screen:      %s\n", zone.ScreenProfile)
225					}
226					if zone.HostInboundTraffic != nil {
227						if len(zone.HostInboundTraffic.SystemServices) > 0 {
228							fmt.Fprintf(buf, "  Host-inbound services: %s\n", strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
229						}
230						if len(zone.HostInboundTraffic.Protocols) > 0 {
231							fmt.Fprintf(buf, "  Host-inbound protocols: %s\n", strings.Join(zone.HostInboundTraffic.Protocols, ", "))
232						}
233					}
```

Runtime trace:

1. Remote operator asks which zone `ge-0/0/0.0` belongs to.
2. gRPC text response prints zone-level host-inbound only.
3. Dataplane may admit based on interface override instead.
4. Operator cannot reconcile observed packet behavior with command output.

Why it matters:

This is the remote equivalent of H06 and directly affects operational debugging.

Suggested fix direction:

Add override rendering to the interface-specific text path and test both zone-level-only and override cases.

Suggested labels: `bug`, `grpc`, `diagnostics`, `host-inbound`, `vsrx-parity`

### H09. Remote `cmd/cli show security zones` drops structured host-inbound fields carried by gRPC

Severity: High  
Confidence: High

Evidence:

`cmd/cli/show.go:475-493`

```go
475	for _, z := range resp.Zones {
476		if z.Id > 0 {
477			fmt.Printf("Zone: %s (id: %d)\n", z.Name, z.Id)
478		} else {
479			fmt.Printf("Zone: %s\n", z.Name)
480		}
481		if z.Description != "" {
482			fmt.Printf("  Description: %s\n", z.Description)
483		}
484		fmt.Printf("  Interfaces: %s\n", strings.Join(z.Interfaces, ", "))
485		if z.TcpRst {
486			fmt.Println("  TCP RST: enabled")
487		}
488		if z.ScreenProfile != "" {
489			fmt.Printf("  Screen: %s\n", z.ScreenProfile)
490		}
491		if len(z.HostInboundServices) > 0 {
492			fmt.Printf("  Host-inbound services: %s\n", strings.Join(z.HostInboundServices, ", "))
493		}
```

Search result confirms the remote CLI does not consume the newer structured fields:

```text
$ rg -n "InterfaceHostInbound|HostInboundConfigured|HostInboundSystemServices|HostInboundProtocols" cmd/cli -S
(no matches)
```

Runtime trace:

1. Server `GetZones` carries `host_inbound_configured`, split service/protocol fields, and `interface_host_inbound`.
2. Remote CLI prints only legacy flattened `HostInboundServices`.
3. It cannot distinguish no-stanza default-deny, explicit empty deny-all, protocol vs system-service, or interface override state.

Why it matters:

Remote CLI is a primary operator surface. Dropping the fields makes the gRPC schema improvement ineffective for humans using the bundled client.

Suggested fix direction:

Teach `cmd/cli` to render `HostInboundConfigured`, split fields, and per-interface override rows. Add golden tests for default-deny/no-stanza, empty stanza, populated stanza, and interface override.

Suggested labels: `bug`, `remote-cli`, `grpc`, `host-inbound`, `vsrx-parity`

### H10. Remote `match-policies` still says unmatched host-inbound local delivery proceeds

Severity: High  
Confidence: High

Evidence:

`cmd/cli/show.go:1144-1148`

```go
1144	} else if resp.HostInboundUnmatched {
1145		// #3285: host-bound traffic — no transit global/default fallback.
1146		fmt.Printf("No matching to-zone junos-host policy for %s -> junos-host\n", req.FromZone)
1147		fmt.Printf("  host-inbound: local delivery proceeds (transit global/default-policy NOT applied)\n")
1148	} else {
```

Repo docs now use the corrected wording elsewhere:

`pkg/grpcapi/README.md:94-100`

```md
94	  `to-zone junos-host` query that matched no host-bound policy (now
95	  `policymatch.HostInboundActionString` — `host-inbound (local delivery subject
96	  to host-inbound-traffic service admission — a zone with no
97	  host-inbound-traffic stanza denies by default; transit/global/default policy
98	  not applied)` instead of an empty action), the no-match host-inbound bit,
99	  default-deny zone, #3405), and the no-active-config case (now `deny (default)` instead of an empty
100	  policy matched and `action` is the configured default-policy (including the
```

Runtime trace:

1. Operator queries remote `show security match-policies from-zone untrust to-zone junos-host ...`.
2. No explicit junos-host policy matches.
3. Server flags `HostInboundUnmatched`.
4. Remote CLI prints "local delivery proceeds" even though host-inbound service admission may still deny, and no-stanza zones deny by default.

Why it matters:

This is an allow/deny diagnostic false positive in a core firewall workflow.

Suggested fix direction:

Reuse the same `policymatch.HostInboundActionString` text or expose server-provided action text to the remote CLI instead of hard-coding.

Suggested labels: `bug`, `remote-cli`, `diagnostics`, `host-inbound`, `vsrx-parity`

### H11. Reject token bucket is consumed before the code knows whether a reject reply can be built

Severity: High  
Confidence: High

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:238-264`

```rust
238	    // #2472: per-reason token-bucket rate limit on the LOCALLY-GENERATED
239	    // reject reply (TCP RST or ICMP/ICMPv6 unreachable). The SYN-cookie
240	    // TX-frame budget gate above is a queue-protection gate (it keeps the
241	    // reply ring from starving transit TX), NOT a per-reason rate cap — under
242	    // a sustained rejected-flow flood it refills as fast as TX drains. The
243	    // token bucket bounds the generated-error RATE so a flood of rejected
244	    // flows cannot be amplified into unbounded RST/ICMP backscatter. Both
245	    // policy and filter reject share this `Reject` bucket (a single emit
246	    // path, per the RejectReplySource doc comment). On bucket-empty we
247	    // fail-closed to the silent drop the caller already performs and bump the
248	    // observable `Reject` rate-limited counter (inside
249	    // `allow_generated_error`).
250	    if !allow_generated_error(GeneratedErrorReason::Reject) {
251	        counters.touched = true;
252	        return false;
253	    }
254	
255	    let bytes = if meta.protocol == PROTO_TCP {
256	        build_reject_rst_frame(packet_frame)
257	    } else {
258	        build_reject_icmp_unreachable(packet_frame, meta, ingress_ifindex, forwarding)
259	    };
260	    let Some(bytes) = bytes else {
261	        // Unparseable frame, ingress without a primary of the inbound
262	        // family, inbound RST/ICMP-error, or a non-first fragment:
263	        // fail-closed to the silent drop the caller already performs.
264	        return false;
```

Runtime trace:

1. Attacker sends packets that hit policy/filter `reject` but are not eligible for a reply, e.g. inbound TCP RSTs, ICMP errors, non-first fragments, or malformed frames.
2. `try_enqueue_reject_reply` checks TX-frame budget, then consumes a `GeneratedErrorReason::Reject` token at line 250.
3. Only after consuming the token does it call `build_reject_*`.
4. Builder returns `None` at line 260 for the documented unreplyable cases.
5. No reject reply is emitted, but the global reject rate-limit bucket was drained.
6. Legitimate subsequent rejects can be silently downgraded to drops because the bucket is empty.

Why it matters:

This is a cheap DoS against active reject behavior. A flood of frames that cannot produce replies can starve valid reject replies, degrading policy semantics and operator diagnostics.

Suggested fix direction:

Move reply-build feasibility before token consumption. Only consume the token after `Some(bytes)` is available and before enqueue. Add tests for RST, ICMP-error, non-first fragment, and malformed frames proving the bucket is not touched.

Suggested labels: `bug`, `security`, `dos`, `firewall`, `userspace-dataplane`, `reject-action`

### H12. Reject TX-frame budget drops are counted before reply feasibility, so impossible replies can look like queue pressure

Severity: High  
Confidence: High

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:225-235`

```rust
225	    if !syn_cookie_reply_budget_available(tx_pipeline) {
226	        counters.touched = true;
227	        // #3615 (L04): attribute the TX-frame-budget suppression to the
228	        // reply's SOURCE so a firewall-filter `then reject` drop is not
229	        // conflated with a policy `then reject` drop. Both still share the
230	        // same budget gate; only the observable counter differs.
231	        match source {
232	            RejectReplySource::Policy => counters.policy_reject_reply_budget_drops += 1,
233	            RejectReplySource::Filter => counters.filter_reject_reply_budget_drops += 1,
234	        }
235	        return false;
```

Build feasibility is checked later:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:255-264`

```rust
255	    let bytes = if meta.protocol == PROTO_TCP {
256	        build_reject_rst_frame(packet_frame)
257	    } else {
258	        build_reject_icmp_unreachable(packet_frame, meta, ingress_ifindex, forwarding)
259	    };
260	    let Some(bytes) = bytes else {
261	        // Unparseable frame, ingress without a primary of the inbound
262	        // family, inbound RST/ICMP-error, or a non-first fragment:
263	        // fail-closed to the silent drop the caller already performs.
264	        return false;
```

Runtime trace:

1. Reject path runs while reply TX budget is exhausted.
2. Packet is actually unreplyable, e.g. non-first fragment.
3. Code increments policy/filter reply-budget-drop counter before trying to build.
4. If budget had been available, the build would have returned `None` anyway.
5. Status/counters blame TX-frame budget pressure for a reply that could not exist.

Why it matters:

Budget-drop counters drive operations. Misattributing malformed/unreplyable traffic as queue pressure can hide the true attack shape and cause wrong remediation.

Suggested fix direction:

Perform reply feasibility before both budget accounting and token consumption. If preserving queue-protection order is necessary, split counters into `reply_budget_drops` and `reply_not_possible_drops`.

Suggested labels: `bug`, `observability`, `counters`, `firewall`, `reject-action`

### H13. `show ... status` omits successful policy/filter reject reply counters that the helper tracks

Severity: High  
Confidence: High

Evidence:

The wire/status object has sent counters:

`pkg/dataplane/userspace/protocol.go:2299-2310`

```go
2299		// #2089: policy `reject` action — RST/ICMP-unreachable replies sent,
2300		// and replies suppressed due to TX-frame budget exhaustion.
2301		PolicyRejectSent uint64 `json:"policy_reject_sent,omitempty"`
2302		// #2521: firewall-filter `then reject` — RST/ICMP-unreachable replies
2303		// sent (mirrors PolicyRejectSent). #3615 (L04/L05): the budget and
2304		// output-filter suppression legs are now SPLIT by source
2305		// (FilterRejectReplyBudgetDrops / FilterRejectOutputFilterDrops) so a
2306		// filter-reject drop is not conflated with a policy-reject drop; the
2307		// parse-error leg stays source-neutral. omitempty + Rust serde `default`
2308		// keep cross-version wire safety.
2309		FilterRejectSent             uint64 `json:"filter_reject_sent,omitempty"`
2310		PolicyRejectReplyBudgetDrops uint64 `json:"policy_reject_reply_budget_drops,omitempty"`
```

Rust increments them:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:325-330`

```rust
325	    counters.touched = true;
326	    match source {
327	        RejectReplySource::Policy => counters.policy_reject_sent += 1,
328	        RejectReplySource::Filter => counters.filter_reject_sent += 1,
329	    }
330	    true
```

But the status formatter declares and aggregates only output-filter drop counters:

`pkg/dataplane/userspace/format/status.go:149-157`

```go
149		// #2238: locally-generated reply output-classification drops.
150		var timeExceededOutputFilterDrops uint64
151		var policyRejectOutputFilterDrops uint64
152		// #3615 (L05): filter-`reject` output-filter drops, split from the policy
153		// leg so filter-reject troubleshooting is precise.
154		var filterRejectOutputFilterDrops uint64
155		var synCookieOutputFilterDrops uint64
156		var ptbOutputFilterDrops uint64
157		var generatedReplyClassifyParseErrors uint64
```

Runtime trace:

1. A policy `then reject` emits TCP RSTs successfully.
2. Rust increments `policy_reject_sent`.
3. Helper status JSON carries `policy_reject_sent`.
4. `show ... status` formatter never aggregates or prints it.
5. Operator sees denies and maybe drops but cannot see active reject success volume.

Why it matters:

For firewall behavior, knowing whether `reject` was actively sent is as important as knowing it was suppressed. Without success counters, operators cannot validate vSRX-style reject behavior under load.

Suggested fix direction:

Aggregate and print `policy_reject_sent` and `filter_reject_sent` near generated-reply counters. Add status formatter tests.

Suggested labels: `bug`, `observability`, `counters`, `firewall`, `vsrx-parity`

### H14. `show ... status` omits policy/filter reject reply-budget drops even though docs say they are shown under Generated-reply drops

Severity: High  
Confidence: High

Evidence:

The status object has budget counters:

`pkg/dataplane/userspace/protocol.go:2309-2313`

```go
2309		FilterRejectSent             uint64 `json:"filter_reject_sent,omitempty"`
2310		PolicyRejectReplyBudgetDrops uint64 `json:"policy_reject_reply_budget_drops,omitempty"`
2311		// #3615 (L04): FILTER-`reject` reply TX-frame-budget suppression, split
2312		// from PolicyRejectReplyBudgetDrops (which is now policy-reject-only).
2313		FilterRejectReplyBudgetDrops uint64 `json:"filter_reject_reply_budget_drops,omitempty"`
```

Formatter output only includes output-filter drops plus parse errors:

`pkg/dataplane/userspace/format/status.go:469-479`

```go
469	if timeExceededOutputFilterDrops != 0 || policyRejectOutputFilterDrops != 0 ||
470		filterRejectOutputFilterDrops != 0 ||
471		synCookieOutputFilterDrops != 0 || ptbOutputFilterDrops != 0 ||
472		generatedReplyClassifyParseErrors != 0 {
473		// #3615 (L05): policy_reject and filter_reject output-filter drops are
474		// reported separately so a firewall-filter `then reject` suppressed by
475		// an egress output filter is not conflated with a policy reject.
476		fmt.Fprintf(&b, "  Generated-reply drops:     time_exceeded=%d policy_reject=%d filter_reject=%d syn_cookie=%d ptb=%d classify_parse_errors=%d\n",
477			timeExceededOutputFilterDrops, policyRejectOutputFilterDrops,
478			filterRejectOutputFilterDrops,
479			synCookieOutputFilterDrops, ptbOutputFilterDrops, generatedReplyClassifyParseErrors)
```

Docs promise budget drops are included:

`docs/junos-cli-reference.md:291-304`

```md
291	  - **Reject-event truthfulness (#3615):** the policy/filter-log RT_FLOW
292	    record reports `action reject` ONLY when the RST/ICMP-unreachable reply was
293	    actually enqueued. If the generated reply fail-closes after the action is
294	    decided (TX-frame budget exhausted, reject rate-limit bucket empty, an
295	    unparseable built frame, or an egress output-filter that discards the
296	    reflected reply), the packet is a silent drop and the event reports the
297	    truthful `action deny` — the forensic log never claims an active reject
298	    that was not sent. Reply-free deny paths (non-first fragments with no L4
299	    header, the forward/output-filter path that has no reply synthesis pending
300	    #3608) log `deny` for the same reason. Suppression is counted per source in
301	    `show ... status`: `policy_reject`/`filter_reject` under the
302	    `Generated-reply drops` line distinguish a policy `then reject` from a
303	    firewall-filter `then reject` that was dropped by budget or an output
304	    filter.
```

Runtime trace:

1. Reject reply is suppressed by TX-frame budget.
2. Rust/JSON counter increments `policy_reject_reply_budget_drops` or `filter_reject_reply_budget_drops`.
3. `show ... status` does not aggregate those fields.
4. Docs say the drop appears under `Generated-reply drops`, but it does not.

Why it matters:

This is a direct observability contract violation. Budget pressure during a flood is exactly when operators need correct counters.

Suggested fix direction:

Add budget counters to the status aggregation and output string, or split into `Generated-reply output-filter drops` and `Generated-reply budget drops`.

Suggested labels: `bug`, `docs-drift`, `observability`, `counters`, `reject-action`

### H15. Prometheus exposes only aggregate reject rate-limit drops, not source-specific reject sent/budget/drop counters

Severity: High  
Confidence: High

Evidence:

`pkg/api/metrics_descriptors.go:1031-1040`

```go
1031		userspaceRejectRateLimited: prometheus.NewDesc(
1032			"xpf_userspace_reject_rate_limited_total",
1033			"Locally-generated policy/filter `reject` replies (TCP RST or "+
1034				"ICMP/ICMPv6 administratively-prohibited unreachable) dropped "+
1035				"because the per-reason token bucket was empty. This is in "+
1036				"ADDITION to the SYN-cookie TX-frame budget gate "+
1037				"(which is queue protection, not a rate cap). A nonzero value "+
1038				"flags a rejected-flow flood being clamped before it amplifies "+
1039				"into unbounded RST/ICMP backscatter (#2472).",
1040			nil, nil,
```

`pkg/api/metrics_userspace.go:588-607`

```go
588	// #2472: locally-generated error-reply per-reason token-bucket drops.
589	// Emitted unconditionally so a 0 is a real "no generated errors
590	// rate-limited" signal rather than an absent series. Nonzero flags an
591	// error-amplification / reflection flood (or a routing loop) being
592	// clamped.
593	ch <- prometheus.MustNewConstMetric(
594		c.userspaceTimeExceededRateLimited,
595		prometheus.CounterValue,
596		float64(status.TimeExceededRateLimitedTotal),
597	)
598	ch <- prometheus.MustNewConstMetric(
599		c.userspacePacketTooBigRateLimited,
600		prometheus.CounterValue,
601		float64(status.PacketTooBigRateLimitedTotal),
602	)
603	ch <- prometheus.MustNewConstMetric(
604		c.userspaceRejectRateLimited,
605		prometheus.CounterValue,
606		float64(status.RejectRateLimitedTotal),
607	)
```

Runtime trace:

1. Policy rejects are working or failing independently from firewall-filter rejects.
2. Rust has source-specific sent and budget-drop counters.
3. Prometheus only exposes a single aggregate `xpf_userspace_reject_rate_limited_total`.
4. Alerting cannot distinguish policy reject starvation from filter reject starvation, nor success from suppression.

Why it matters:

Security appliances need counters that map to policy/action source. Aggregate-only reject telemetry makes it hard to prove whether a policy is behaving correctly during attack traffic.

Suggested fix direction:

Expose `xpf_userspace_reject_sent_total{source="policy|filter"}`, `xpf_userspace_reject_reply_budget_drops_total{source=...}`, `xpf_userspace_reject_output_filter_drops_total{source=...}`, and preserve aggregate rate-limited only if source cannot be split yet.

Suggested labels: `bug`, `metrics`, `observability`, `firewall`, `vsrx-parity`

## Medium Confidence Findings

### M01. Shared global reject bucket lets firewall-filter rejects starve security-policy rejects

Severity: Medium  
Confidence: Medium

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:243-250`

```rust
243	    // token bucket bounds the generated-error RATE so a flood of rejected
244	    // flows cannot be amplified into unbounded RST/ICMP backscatter. Both
245	    // policy and filter reject share this `Reject` bucket (a single emit
246	    // path, per the RejectReplySource doc comment). On bucket-empty we
247	    // fail-closed to the silent drop the caller already performs and bump the
248	    // observable `Reject` rate-limited counter (inside
249	    // `allow_generated_error`).
250	    if !allow_generated_error(GeneratedErrorReason::Reject) {
```

`userspace-dp/src/afxdp/icmp_ratelimit.rs:163-172`

```rust
163	static TIME_EXCEEDED_BUCKET: TokenBucket = TokenBucket::new();
164	static PACKET_TOO_BIG_BUCKET: TokenBucket = TokenBucket::new();
165	static REJECT_BUCKET: TokenBucket = TokenBucket::new();
166	
167	fn bucket_for(reason: GeneratedErrorReason) -> &'static TokenBucket {
168	    match reason {
169	        GeneratedErrorReason::TimeExceeded => &TIME_EXCEEDED_BUCKET,
170	        GeneratedErrorReason::PacketTooBig => &PACKET_TOO_BIG_BUCKET,
171	        GeneratedErrorReason::Reject => &REJECT_BUCKET,
172	    }
```

Runtime trace:

1. Attacker floods traffic that hits an input/lo0 firewall filter with `then reject`.
2. Every eligible filter reject consumes from the single `REJECT_BUCKET`.
3. Unrelated security policy `then reject` traffic arrives while the bucket is empty.
4. Policy reject silently downgrades to deny/drop because filter traffic exhausted the shared budget.

Why it matters:

Policy reject and filter reject are distinct operator features. A noisy control-plane filter should not completely starve policy-level reject semantics unless the contract says this is intentional.

Suggested fix direction:

Split the bucket by `RejectReplySource`, or reserve a minimum policy quota. At minimum, document the shared bucket explicitly in CLI/docs and expose source-aware drops.

Suggested labels: `security`, `firewall-filter`, `policy`, `reject-action`, `vsrx-parity`

### M02. Source-neutral `RejectRateLimitedTotal` hides whether policy or filter reject exhausted the shared bucket

Severity: Medium  
Confidence: Medium

Evidence:

`userspace-dp/src/afxdp/icmp_ratelimit.rs:175-184`

```rust
175	/// Returns true when a locally-generated error reply for `reason` MAY be sent
176	/// (a token was available), false when it MUST be dropped because the
177	/// per-reason bucket is empty. On a deny the per-reason `rate_limited` counter
178	/// is bumped so the suppression is observable via the coordinator status.
179	///
180	/// Uses the compile-time `DEFAULT_RATE_PER_SEC` / `DEFAULT_BURST`. The bucket
181	/// is global-per-reason (no per-source state), matching Linux's
182	/// `icmp_msgs_per_sec` model.
183	pub(in crate::afxdp) fn allow_generated_error(reason: GeneratedErrorReason) -> bool {
184	    allow_generated_error_at(reason, monotonic_nanos(), DEFAULT_RATE_PER_SEC, DEFAULT_BURST)
```

`pkg/api/metrics_userspace.go:603-607`

```go
603	ch <- prometheus.MustNewConstMetric(
604		c.userspaceRejectRateLimited,
605		prometheus.CounterValue,
606		float64(status.RejectRateLimitedTotal),
607	)
```

Runtime trace:

1. Reject bucket empties.
2. Helper increments one source-neutral counter.
3. Prometheus and status cannot tell whether policy or filter traffic caused the suppression.
4. Operator sees a flood but not which config feature is being clamped.

Why it matters:

This is not just cosmetic. Source attribution determines whether to tune firewall filters, security policies, or generated-reply rate caps.

Suggested fix direction:

Track source-specific rate-limit drops at the caller where `RejectReplySource` is known. Keep the aggregate for backward compatibility.

Suggested labels: `observability`, `metrics`, `firewall`, `reject-action`

### M03. Text zone views do not show that no-stanza configured zones are default-deny

Severity: Medium  
Confidence: Medium

Evidence:

Local CLI only prints host-inbound when a zone-level stanza exists:

`pkg/cli/cli_show_security_zones.go:63-72`

```go
63		if zone.HostInboundTraffic != nil {
64			if len(zone.HostInboundTraffic.SystemServices) > 0 {
65				fmt.Printf("  Allowed host-inbound traffic: %s\n",
66					strings.Join(zone.HostInboundTraffic.SystemServices, " "))
67			}
68			if len(zone.HostInboundTraffic.Protocols) > 0 {
69				fmt.Printf("  Allowed host-inbound protocols: %s\n",
70					strings.Join(zone.HostInboundTraffic.Protocols, " "))
71			}
72		}
```

gRPC text mirrors that behavior:

`pkg/grpcapi/server_show_zones_text.go:63-72`

```go
63		if zone.HostInboundTraffic != nil {
64			if len(zone.HostInboundTraffic.SystemServices) > 0 {
65				fmt.Fprintf(buf, "  Host-inbound system-services: %s\n",
66					strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
67			}
68			if len(zone.HostInboundTraffic.Protocols) > 0 {
69				fmt.Fprintf(buf, "  Host-inbound protocols: %s\n",
70					strings.Join(zone.HostInboundTraffic.Protocols, ", "))
71			}
72		}
```

Runtime trace:

1. Configured zone has no host-inbound stanza.
2. Dataplane denies all non-global host-bound services by default.
3. Text output prints no host-inbound line at all.
4. Operator cannot distinguish "not shown" from "not enforced" without knowing #3405 internals.

Why it matters:

For default-deny parity, absence of a line is not a safe representation. vSRX-style output should make the control-plane protection posture explicit.

Suggested fix direction:

Print `Host-inbound: default deny (no stanza)` for configured zones with no stanza, and `Host-inbound: deny all (empty stanza)` for explicit empty stanzas if that distinction remains useful.

Suggested labels: `observability`, `cli`, `grpc`, `host-inbound`, `vsrx-parity`

### M04. Zone detail policy summary omits global policies that can affect the zone

Severity: Medium  
Confidence: Medium

Evidence:

`pkg/cli/cli_show_security_zones.go:148-180`

```go
148			// Policy detail breakdown
149			fmt.Println("  Policy summary:")
150			totalPolicies := 0
151			for _, zpp := range cfg.Security.Policies {
152				// #3476: skip a nil zone-pair set (tolerant / HA-sync config
153				// path the runtime walker skips) rather than dereferencing
154				// zpp.FromZone.
155				if zpp == nil {
156					continue
157				}
158				if zpp.FromZone == name || zpp.ToZone == name {
159					for _, pol := range zpp.Policies {
160						// #3476: skip a nil rule rather than dereferencing
161						// pol.Action / pol.Name.
162						if pol == nil {
163							continue
164						}
165						action := "permit"
166						switch pol.Action {
167						case 1:
168							action = "deny"
169						case 2:
170							action = "reject"
171						}
172						fmt.Printf("    %s -> %s: %s (%s)\n",
173							zpp.FromZone, zpp.ToZone, pol.Name, action)
174						totalPolicies++
175					}
176				}
177			}
178			if totalPolicies == 0 {
179				fmt.Println("    (no policies)")
180			}
```

Runtime trace:

1. Zone has no zone-pair policies but has an applicable global policy, possibly scoped by from/to zone.
2. Runtime evaluator considers zone-pair, then global, then default policy.
3. `show security zones detail` scans only `cfg.Security.Policies`.
4. Output says `(no policies)` or omits the global policy that can decide traffic.

Why it matters:

A zone-centric audit should not hide a policy tier that can permit or deny packets for that zone.

Suggested fix direction:

Include applicable global policies in zone detail, honoring scoped `match from-zone`/`to-zone`. Mark them as global tier so operators do not confuse them with zone-pair policies.

Suggested labels: `feature-gap`, `cli`, `global-policy`, `firewall`, `vsrx-parity`

### M05. Zone detail policy summary omits the effective default-policy catch-all

Severity: Medium  
Confidence: Medium

Evidence:

Same code path as M04 ends with `(no policies)` when no zone-pair policies are present:

`pkg/cli/cli_show_security_zones.go:172-180`

```go
172						fmt.Printf("    %s -> %s: %s (%s)\n",
173							zpp.FromZone, zpp.ToZone, pol.Name, action)
174						totalPolicies++
175					}
176				}
177			}
178			if totalPolicies == 0 {
179				fmt.Println("    (no policies)")
180			}
```

REST policy inventory now has explicit synthetic default-policy rows:

`pkg/api/security.go:323-337`

```go
323	// #3363: the IMPLICIT default-policy catch-all now has a reserved hit
324	// counter (read via the DefaultPolicySentinelID handle). Surface it as a
325	// synthetic policy row with reserved id/name so REST clients can show the
326	// dataplane.DefaultPolicyName so automation/dashboards can audit
327	// configured default-policy behavior.
328	if includeDefault {
329		out = append(out, PolicyInfo{
330			Name:         dataplane.DefaultPolicyName,
331			Action:       policyActionStr(cfg.Security.DefaultPolicy),
332			FromZone:     "-",
333			ToZone:       "-",
334			Applications: []string{"any"},
335			PolicyID:     dataplane.DefaultPolicySentinelID,
336			RuleID:       dataplane.DefaultPolicyName,
337		})
```

Runtime trace:

1. No explicit zone-pair policies are configured for a zone.
2. Default policy still decides unmatched transit packets.
3. REST inventory can surface the default-policy sentinel.
4. CLI zone detail says `(no policies)`, hiding the effective catch-all.

Why it matters:

For a router/firewall, `(no policies)` is materially different from `default-policy deny-all` or `permit-all`.

Suggested fix direction:

Add an explicit default-policy line to zone detail after zone/global summaries.

Suggested labels: `observability`, `cli`, `default-policy`, `firewall`, `vsrx-parity`

### M06. Remote CLI cannot distinguish host-inbound system-services from protocols

Severity: Medium  
Confidence: Medium

Evidence:

Remote CLI prints only the flattened legacy field:

`cmd/cli/show.go:491-493`

```go
491		if len(z.HostInboundServices) > 0 {
492			fmt.Printf("  Host-inbound services: %s\n", strings.Join(z.HostInboundServices, ", "))
493		}
```

Proto carries split fields:

`proto/xpf/v1/xpf.proto:238-246`

```proto
238	  // host_inbound_system_services / host_inbound_protocols (#3328) carry the
239	  // ZONE-LEVEL admission set, kept distinct so automation can tell a
240	  // system-service (ssh, ping, dhcp) apart from a routing protocol (ospf,
241	  // bgp). Empty when the zone has no zone-level stanza (e.g. host-inbound is
242	  // expressed only via per-interface overrides below).
243	  repeated string host_inbound_system_services = 13;
244	  repeated string host_inbound_protocols = 14;
245	  // interface_host_inbound (#3328, #3362) carries per-interface host-inbound
246	  // overrides. An entry exists only for an interface that declares its own
```

Runtime trace:

1. Zone allows protocol `ospf` and system-service `ssh`.
2. gRPC server returns split fields.
3. Remote CLI collapses to `HostInboundServices`, losing the service/protocol distinction.
4. Operator cannot tell whether a routing protocol or management service is admitted.

Why it matters:

vSRX/Junos separates `system-services` and `protocols` for a reason: they have different operational meaning and security review owners.

Suggested fix direction:

Render split fields separately in `cmd/cli`, preserving legacy flattened output only as compatibility if needed.

Suggested labels: `feature-gap`, `remote-cli`, `host-inbound`, `vsrx-parity`

### M07. Text surfaces lack tests for per-interface host-inbound rendering

Severity: Medium  
Confidence: Medium

Evidence:

Search finds structured tests, but no local CLI/gRPC text/remote CLI tests for rendering the override:

```text
$ rg -n "interface_host_inbound|HostInboundConfigured|per-interface host-inbound|Host-inbound" pkg/cli pkg/grpcapi cmd/cli -g '*_test.go' -S
pkg/grpcapi/server_matchpolicies_queried_zones_3627_test.go:45:    // Host-inbound: to-zone junos-host with no host policy -> local delivery.
pkg/grpcapi/server_show_zones_hostinbound_3328_test.go:17:// host_inbound_protocols, and interface_host_inbound (#3362). These are the
pkg/grpcapi/server_show_zones_hostinbound_3328_test.go:84:    if !trust.GetHostInboundConfigured() {
pkg/grpcapi/server_show_zones_hostinbound_3328_test.go:101:   if !locked.GetHostInboundConfigured() {
pkg/grpcapi/server_show_zones_hostinbound_3328_test.go:113:   if open.GetHostInboundConfigured() {
pkg/grpcapi/server_show_zones_hostinbound_3328_test.go:121:   if !edge.GetHostInboundConfigured() {
pkg/grpcapi/server_show_zones_hostinbound_3328_test.go:129:       t.Fatalf("edge interface_host_inbound = %v, want 1 entry (#3328 per-interface override dropped)", edge.GetInterfaceHostInbound())
```

Runtime trace:

1. Structured `GetZones` tests cover interface override rows.
2. Local CLI, gRPC text, and remote CLI renderers drift independently.
3. No golden test fails when those renderers omit the override.
4. H04-H09 survive despite structured tests.

Why it matters:

Operator-facing CLI drift is likely without golden tests, especially when the structured model evolves faster than text renderers.

Suggested fix direction:

Add golden tests for local `show security zones detail`, local `show interfaces`, local `test security-zone interface`, gRPC text show zones/interface, and remote `cmd/cli show security zones`.

Suggested labels: `test-gap`, `cli`, `grpc`, `host-inbound`

### M08. Reject sent/budget fields have no status/metrics tests, so formatter drift is not caught

Severity: Medium  
Confidence: Medium

Evidence:

Search only finds tests for aggregate `RejectRateLimitedTotal`, not policy/filter sent or budget fields:

```text
$ rg -n "policy_reject_sent|filter_reject_sent|reply_budget_drops|RejectRateLimited" pkg/api pkg/dataplane/userspace/format -g '*_test.go' -S
pkg/api/metrics_test.go:904:        userspaceRejectRateLimited: prometheus.NewDesc(
pkg/api/metrics_test.go:957:        RejectRateLimitedTotal:       13,
pkg/api/metrics_test.go:1033:       assertCounterClose(t, got, c.userspaceRejectRateLimited, nil, 13)
```

`pkg/api/metrics_test.go:953-1000` fixture exercises only the aggregate rate-limit side:

```go
953		TimeExceededRateLimitedTotal: 11,
954		PacketTooBigRateLimitedTotal: 12,
955		RejectRateLimitedTotal:       13,
956	}
957	got := collectUserspaceMetrics(t, c, status)
958	assertCounterClose(t, got, c.userspaceTimeExceededRateLimited, nil, 11)
959	assertCounterClose(t, got, c.userspacePacketTooBigRateLimited, nil, 12)
960	assertCounterClose(t, got, c.userspaceRejectRateLimited, nil, 13)
```

Runtime trace:

1. Developer adds or changes reject counters in helper protocol.
2. Formatter/metrics omit or mislabel some counters.
3. Existing tests remain green because they only check aggregate rate-limited metric.
4. Operator output drifts from helper truth.

Why it matters:

The reject path is used under attack/flood conditions. Missing tests around source-specific counters make regressions likely.

Suggested fix direction:

Add unit tests for status formatter and Prometheus collector using all reject fields: sent, budget drops, output-filter drops, and rate-limit drops.

Suggested labels: `test-gap`, `metrics`, `status`, `reject-action`

### M09. README/API docs still describe no-stanza host-inbound as admit-all

Severity: Medium  
Confidence: Medium

Evidence:

`pkg/api/README.md:80-89`

```md
80	  - `GET /api/v1/security/zones` enumerates security zones (`ZoneInfo`,
81	    types.go). The host-inbound admission set is surfaced distinctly
82	    (#3328): `host_inbound_configured` is the dataplane posture bit
83	    (mirrors `ZoneSnapshot.HostInboundConfigured`, #3070/#3362) — true
84	    when the zone declares a `host-inbound-traffic` stanza OR carries any
85	    per-interface override. This lets automation tell apart the three
86	    postures the dataplane actually models: no stanza
87	    (`host_inbound_configured=false` -> admit-all for host-bound traffic),
88	    explicit empty stanza (`configured=true` with empty lists -> deny-all),
89	    and a populated set. `host_inbound_system_services` and
```

`pkg/grpcapi/README.md:175-183`

```md
175	- `GetZones` enumerates security zones (`ZoneInfo`). The host-inbound
176	  admission set is surfaced distinctly (#3328): `host_inbound_configured`
177	  is the dataplane posture bit (mirrors `ZoneSnapshot.HostInboundConfigured`,
178	  #3070/#3362) — true when the zone declares a `host-inbound-traffic`
179	  stanza OR carries any per-interface override. It lets a controller tell
180	  apart the three postures the dataplane models: no stanza
181	  (`configured=false` -> admit-all for host-bound traffic), explicit empty
182	  stanza (`configured=true` with empty lists -> deny-all), and a populated
183	  set. `host_inbound_system_services` / `host_inbound_protocols` carry the
```

Runtime trace:

1. Operator reads README docs after #3405.
2. Docs say no stanza admits all host-bound traffic.
3. Runtime denies all host-bound traffic for configured zones with no stanza.
4. Documentation misleads config migration and support.

Why it matters:

This can cause operators to misdiagnose management lockout or unintentionally depend on a security posture that no longer exists.

Suggested fix direction:

Update both README sections to the #3405 contract and point to explicit lifeline/global ICMP exceptions separately.

Suggested labels: `docs`, `host-inbound`, `vsrx-parity`

## Low Confidence Findings

### L01. Rust host-inbound unit test comments imply interface override replaces zone set, while Go wire contract says it sends the effective union

Severity: Low  
Confidence: Low

Evidence:

Rust doc says the interface map is pre-unioned in Go:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:493-501`

```rust
493	/// #3362: per-packet host-inbound admit keyed by INGRESS INTERFACE first. When
494	/// the ingress interface carries a per-interface host-inbound OVERRIDE
495	/// (`state.ifindex_host_inbound`), the packet is matched against that interface's
496	/// EFFECTIVE admission set (zone union interface, pre-unioned in Go); otherwise it
497	/// falls back to the zone-keyed [`host_inbound_admits`]. The global
498	/// ICMP/PMTUD/ND accept (#3171) is applied first in BOTH branches so error / ND
499	/// delivery is never broken by a scoped override. This is the entry point the
500	/// local-delivery poll path uses; `host_inbound_admits` stays the zone-only
501	/// primitive (and the direct test target).
```

But the Rust test manually inserts a non-unioned override and describes it as replacement:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:692-703`

```rust
692	            ZONE,
693	            zone_host_inbound_from_tokens(&["ping".to_string()], &[]),
694	        );
695	        // Per-interface override on the uplink: ssh only.
696	        state.ifindex_host_inbound.insert(
697	            IFINDEX_UPLINK,
698	            zone_host_inbound_from_tokens(&["ssh".to_string()], &[]),
699	        );
700	
701	        // Uplink (override present): admits ssh, denies https, and does NOT
702	        // inherit the zone's ping (the override REPLACES the zone set on this
703	        // interface — its set is the Go-side effective union).
```

Go wire test expects union:

`pkg/dataplane/userspace/host_inbound_per_iface_3362_test.go:115-120`

```go
115	over := byName["reth0.50"]
116	if !over.HostInboundConfigured {
117		t.Fatal("overridden interface reth0.50 must carry host_inbound_configured=true on the wire")
118	}
119	if !eqStr(over.HostInboundSystemServices, []string{"ping", "ssh"}) {
120		t.Errorf("wire effective services = %v, want [ping ssh] (zone union interface)", over.HostInboundSystemServices)
```

Runtime trace:

1. Production Go sends effective union for interface override.
2. Rust unit test constructs state directly and uses replacement semantics.
3. A future Go/Rust contract drift could remain unclear because the Rust unit test is not modeling production wire data.

Why it matters:

The data path may be correct today, but tests and comments disagree enough to create future regression risk in a security-critical override feature.

Suggested fix direction:

Adjust Rust test fixture to insert `[ping, ssh]` as the interface effective set, and add a separate unit test documenting that Rust treats interface map as authoritative precomputed effective data.

Suggested labels: `test-gap`, `host-inbound`, `docs`, `vsrx-parity`

### L02. Zone/global/default policy rendering is fragmented across REST, gRPC, local CLI, and remote CLI

Severity: Low  
Confidence: Low

Evidence:

REST has explicit global/default inventory logic:

`pkg/api/security.go:256-261`

```go
256	if len(cfg.Security.GlobalPolicies) > 0 {
257		globalSetID := policySetID
258		for i, rule := range cfg.Security.GlobalPolicies {
259			if rule == nil { // #3493: tolerant/HA-sync path may carry a nil policy
260				continue
261			}
```

Local zone detail has a separate hand-written zone-pair-only loop:

`pkg/cli/cli_show_security_zones.go:148-158`

```go
148			// Policy detail breakdown
149			fmt.Println("  Policy summary:")
150			totalPolicies := 0
151			for _, zpp := range cfg.Security.Policies {
152				// #3476: skip a nil zone-pair set (tolerant / HA-sync config
153				// path the runtime walker skips) rather than dereferencing
154				// zpp.FromZone.
155				if zpp == nil {
156					continue
157				}
158				if zpp.FromZone == name || zpp.ToZone == name {
```

Runtime trace:

1. A new policy field or tier is added to REST inventory.
2. Local CLI/gRPC text/remote CLI each have separate loops and can miss it.
3. Operators see different policy truth depending on surface.

Why it matters:

This exact fragmentation produced several findings above. A shared presenter would reduce future drift.

Suggested fix direction:

Create a `security/presentation` or `pkg/security/inventory` package that returns typed zone policy rows for all surfaces, then render text/JSON/proto from that model.

Suggested labels: `refactor`, `modularity`, `firewall`, `observability`

### L03. Host-inbound source/state should be modeled explicitly instead of inferred from booleans and nil pointers

Severity: Low  
Confidence: Low

Evidence:

REST computes posture from config shape:

`pkg/api/security.go:51-60`

```go
51		if zone.HostInboundTraffic != nil {
52			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.SystemServices...)
53			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.Protocols...)
54			zi.HostInboundSystemServices = append(zi.HostInboundSystemServices, zone.HostInboundTraffic.SystemServices...)
55			zi.HostInboundProtocols = append(zi.HostInboundProtocols, zone.HostInboundTraffic.Protocols...)
56		}
57		// HostInboundConfigured mirrors ZoneSnapshot.HostInboundConfigured
58		// (#3070/#3362): the zone is host-inbound ENFORCING when it declares a
59		// zone-level stanza OR carries any per-interface override.
60		zi.HostInboundConfigured = zone.HostInboundTraffic != nil || len(zone.InterfaceHostInbound) > 0
```

Dataplane compiler uses runtime enforcement posture independent of stanza source:

`pkg/dataplane/userspace/zones.go:494-500`

```go
494		if zone := cfg.Security.Zones[name]; zone != nil {
495			zs.HostInboundConfigured = true
496			if zone.HostInboundTraffic != nil {
497				zs.HostInboundSystemServices = lowerTokens(zone.HostInboundTraffic.SystemServices)
498				zs.HostInboundProtocols = lowerTokens(zone.HostInboundTraffic.Protocols)
499			}
500		}
```

Runtime trace:

1. Same boolean name is used for enforcement posture and config-source inference.
2. #3405 changed enforcement posture but not all source inference users.
3. API/docs/tests drift.

Why it matters:

A single bool cannot accurately encode no-stanza default-deny, explicit empty deny-all, zone tokens, interface override, and effective per-interface union.

Suggested fix direction:

Add typed fields: `host_inbound_enforced bool`, `host_inbound_source enum`, and per-interface `effective_*` fields. Deprecate ambiguous interpretations of `host_inbound_configured`.

Suggested labels: `api-design`, `host-inbound`, `refactor`, `vsrx-parity`

### L04. Reject counter inventory should be generated from the wire struct or a shared counter registry

Severity: Low  
Confidence: Low

Evidence:

Wire struct includes counters not represented in format/metrics:

`pkg/dataplane/userspace/protocol.go:2299-2313`

```go
2299		// #2089: policy `reject` action — RST/ICMP-unreachable replies sent,
2300		// and replies suppressed due to TX-frame budget exhaustion.
2301		PolicyRejectSent uint64 `json:"policy_reject_sent,omitempty"`
2302		// #2521: firewall-filter `then reject` — RST/ICMP-unreachable replies
2303		// sent (mirrors PolicyRejectSent). #3615 (L04/L05): the budget and
2304		// output-filter suppression legs are now SPLIT by source
2305		// (FilterRejectReplyBudgetDrops / FilterRejectOutputFilterDrops) so a
2306		// filter-reject drop is not conflated with a policy-reject drop; the
2307		// parse-error leg stays source-neutral. omitempty + Rust serde `default`
2308		// keep cross-version wire safety.
2309		FilterRejectSent             uint64 `json:"filter_reject_sent,omitempty"`
2310		PolicyRejectReplyBudgetDrops uint64 `json:"policy_reject_reply_budget_drops,omitempty"`
2311		// #3615 (L04): FILTER-`reject` reply TX-frame-budget suppression, split
2312		// from PolicyRejectReplyBudgetDrops (which is now policy-reject-only).
2313		FilterRejectReplyBudgetDrops uint64 `json:"filter_reject_reply_budget_drops,omitempty"`
```

Formatter has a hand-written subset:

`pkg/dataplane/userspace/format/status.go:149-157`

```go
149		// #2238: locally-generated reply output-classification drops.
150		var timeExceededOutputFilterDrops uint64
151		var policyRejectOutputFilterDrops uint64
152		// #3615 (L05): filter-`reject` output-filter drops, split from the policy
153		// leg so filter-reject troubleshooting is precise.
154		var filterRejectOutputFilterDrops uint64
155		var synCookieOutputFilterDrops uint64
156		var ptbOutputFilterDrops uint64
157		var generatedReplyClassifyParseErrors uint64
```

Runtime trace:

1. New helper counter is added.
2. Wire JSON receives it.
3. Every status/metrics renderer must be manually updated.
4. If a renderer is missed, no compile failure occurs.

Why it matters:

The userspace dataplane already has a broad and growing counter set. Manual duplication is causing missed operator signals.

Suggested fix direction:

Introduce a generated or declarative counter registry with names, help text, status grouping, and Prometheus mapping. Generate format and metrics tests from the same table.

Suggested labels: `refactor`, `observability`, `metrics`, `userspace-dataplane`

### L05. Per-interface host-inbound output should include effective source, not only raw configured tokens

Severity: Low  
Confidence: Low

Evidence:

Production wire says interface set is effective union:

`pkg/dataplane/userspace/host_inbound_per_iface_3362_test.go:115-120`

```go
115	over := byName["reth0.50"]
116	if !over.HostInboundConfigured {
117		t.Fatal("overridden interface reth0.50 must carry host_inbound_configured=true on the wire")
118	}
119	if !eqStr(over.HostInboundSystemServices, []string{"ping", "ssh"}) {
120		t.Errorf("wire effective services = %v, want [ping ssh] (zone union interface)", over.HostInboundSystemServices)
```

REST/gRPC per-interface rows carry lists, but not whether the token came from zone or interface:

`pkg/api/security.go:61-68`

```go
61		for _, ref := range zone.SortedInterfaceHostInboundRefs() {
62			hib := zone.InterfaceHostInbound[ref]
63			zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, ZoneInterfaceHostInbound{
64				Interface:      ref,
65				Configured:     true,
66				SystemServices: append([]string{}, hib.SystemServices...),
67				Protocols:      append([]string{}, hib.Protocols...),
68			})
```

Runtime trace:

1. Zone allows `ping`; interface adds `ssh`.
2. Effective interface set is `[ping, ssh]`.
3. API returns one list but does not identify inherited vs interface-local tokens.
4. Operator cannot tell which stanza to edit to remove `ping` vs `ssh` from that interface.

Why it matters:

This is a feature completeness issue rather than a direct enforcement bug. vSRX-style operations benefit from showing both configured and inherited admission state.

Suggested fix direction:

Expose `zone_inherited_*`, `interface_configured_*`, and `effective_*` lists, or include a token-source map for per-interface rows.

Suggested labels: `feature-gap`, `host-inbound`, `api`, `grpc`, `vsrx-parity`

## Suggested Issue Split

1. `bug(host-inbound): align REST/gRPC host_inbound_configured with #3405 configured-zone default deny` (H01, H02, H03, M09).
2. `bug(cli): render per-interface host-inbound overrides in local zone/interface diagnostics` (H04, H05, H06, M03, M07).
3. `bug(grpc/remote-cli): render per-interface and split host-inbound fields in text/remote clients` (H07, H08, H09, H10, M06, M07).
4. `bug(reject): build reject reply before consuming rate/budget accounting for unreplyable frames` (H11, H12).
5. `observability(reject): expose policy/filter reject sent, budget, output-filter, and rate-limit counters consistently` (H13, H14, H15, M01, M02, M08, L04).
6. `feature(cli): include global and default-policy tiers in zone detail policy summary` (M04, M05).
7. `refactor(host-inbound): model enforcement posture/source/effective tokens explicitly` (L01, L03, L05).

