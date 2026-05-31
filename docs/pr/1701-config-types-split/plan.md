# #1701 — Split `pkg/config/types.go` (2055 LOC) by domain

**Status:** DRAFT v1 — pending adversarial plan review

## 1. Issue framing

`pkg/config/types.go` is 2055 LOC — the single typed config model for the
whole control plane. Nearly every package (`grep` finds 194 consumer files
outside `pkg/config/` referencing the `config` package) imports these
types as `config.Foo`. The issue asks to split the typed structs by domain
(interfaces / security / routing / cos / system) into cohesive
`config/types_*.go` files **or** a sub-package, with the central guard
that the split introduces **no import cycles** and **no public-type churn
for consumers**. PLAN-KILL if the types do not decompose without breaking
the consumer API.

This is the WAVE-2 sibling of the just-merged #1699 ast.go split (master
@ `f96e0e04`). The same approach #1699 used — byte-identical block motion
into same-package sibling files — is the natural fit here and is what this
plan proposes.

## 2. Honest scope/value framing

This is a pure maintainability/navigability refactor. No runtime behavior
changes, no perf delta — `types.go` is compiled identically whether it is
one file or seven in the same package. The win is:

- 2055 LOC → ~7 files of 150–450 LOC each, grouped by Junos config domain,
  so a contributor editing NAT types is not scrolling past SNMP and OSPF.
- Lower merge-conflict surface for the parallel refactor backlog (sibling
  PRs #1697/#1698/#1700 touch other large files; domain files reduce the
  odds two PRs touch the same file).
- Mirrors the established `compiler_*.go`, `parser_*_test.go`, and #1699
  `ast_*.go` / `schema*.go` layout already in `pkg/config/`.

If reviewers conclude the maintainability gain is too small to justify the
churn, **PLAN-KILL is an acceptable verdict.** The counter-argument that a
type-only file is "fine at 2055 LOC because go tooling indexes it" is
legitimate; the repo's own `docs/engineering-style.md` modularity
discipline (files > ~2000 LOC trigger refactor) is the standing rationale
for doing it.

## 3. Decomposition strategy — pure same-package intra-file motion

**Sub-package is explicitly rejected.** Moving any type to `config/types`
(or similar) would force every one of the 194 consumer files to either
re-import and rename `config.Foo` → `types.Foo`, OR require a sea of type
aliases (`type Foo = types.Foo`) in `package config` that defeats the
point. Worse, the `config` package's own `compiler_*.go`, `schema*.go`,
`ast*.go`, and `parser*.go` files freely reference these types and ALSO
construct/mutate them — a sub-package split risks an import cycle the
instant a type method needs a parser/AST helper, or the AST layer needs a
typed struct. **Same-package sibling files have none of these hazards:**
the types stay `config.Foo`, every consumer is untouched, and there is no
new import edge anywhere in the graph.

This is identical in shape to #1699 (which split `ast.go` into
`ast.go` + `ast_edit.go` + `ast_format.go` + `ast_groups.go` + `schema.go`
+ `schema_complete.go`, all `package config`).

### Proposed file layout (all `package config`)

| File | Contents (domains) | Approx LOC |
|------|--------------------|-----------|
| `types.go` (kept) | `Config` root struct + interface-name/resolution helpers: `LinuxIfName`, `InterfaceSlot`, `SlotToNodeID`, `(*Config).RethToPhysical`, `ResolveReth`, `ResolveFab`, `ResolveKernelIfName`, `DHCPLeaseKey`, `IRBToBridge`, `(*Config).TunnelNameMap` | ~340 |
| `types_chassis.go` | `ChassisConfig`, `ClusterConfig`, `RedundancyGroup`, `InterfaceMonitor`, `IPMonitoring`, `IPMonitorTarget`, `EventPolicy`, `EventWithin`, `BridgeDomainConfig` | ~110 |
| `types_interfaces.go` | `InterfacesConfig`, `InterfaceConfig`, `AggregatedEtherOptions`, `InterfaceUnit`, `VRRPGroup`, `DHCPv6ClientConfig`, `DHCPInetOptions` | ~100 |
| `types_security.go` | `SecurityConfig`, `FlowConfig`, `FlowTraceoptions`, `TracePacketFilter`, `ALGConfig`, `TCPSessionConfig`, `LogConfig`, `SyslogTransport`, `SyslogStream`, `SSHKnownHostKey`, `PreIDDefaultPolicy`, `ZoneConfig`, `HostInboundTraffic`, `ZonePairPolicies`, `Policy`, `PolicyMatch`, `PolicyAction`+const, `PolicyLog`, all NAT (`NATConfig` … `StaticNATRule`, `NATType`+const), all Screen (`LimitSessionScreen` … `SynFloodConfig`), `AddressBook`, `Address`, `AddressSet`, `ApplicationsConfig`, `ApplicationSet`, `Application` | ~470 |
| `types_routing.go` | `PolicyOptionsConfig`, `ASPathDef`, `CommunityDef`, `PrefixList`, `PolicyStatement`, `PolicyTerm`, `RouteFilter`, `RoutingOptionsConfig`, `GenerateRoute`, `RibGroup`, `NextHopEntry`, `StaticRoute`, `ProtocolsConfig`, `LLDPConfig`/`LLDPInterface`, OSPFv3/`RIPConfig`/ISIS, `RAInterfaceConfig`/`RAPrefix`, OSPF, BGP, `TunnelConfig`, `IPsecConfig` … `IPsecVPN`, `RoutingInstanceConfig` | ~430 |
| `types_cos.go` | `SchedulerConfig`, `ClassOfServiceConfig`, `CoSForwardingClass`, all `CoS*` classifier/rewrite/scheduler/interface types, `CoSFairnessExpectation` | ~150 |
| `types_system.go` | `SystemConfig`, `UserspaceConfig`, `SharedUMEMConfig`, `RootAuthConfig`, `ArchivalConfig`, `InternetOptionsConfig`, `SystemServicesConfig`, `SSHServiceConfig`, `WebManagementConfig`, `APIAuthConfig`/`APIAuthUser`, syslog/`SNMP*`, `LoginClassPermission`+const+`LoginClassPermissions` var, `LoginConfig`/`LoginUser`, `ServicesConfig`, RPM (`RPMConfig`/`RPMProbe`/`RPMTest`+6 `Effective*` methods+`Default*` const block), flow-monitoring/NetFlow, `ForwardingOptionsConfig`/port-mirror, DHCP relay, sampling, `FirewallConfig` … `PrefixListRef`, DHCP server, dynamic-address feeds | ~450 |

Domain assignment follows the `Config` root struct's own field grouping
(`Security`, `Interfaces`, `RoutingOptions`+`Protocols`+`RoutingInstances`,
`ClassOfService`, `System`+`Services`+`ForwardingOptions`+`Firewall`,
`Chassis`+`EventOptions`+`BridgeDomains`). `Firewall`/`Services`/
`ForwardingOptions`/DHCP-server land in `types_system.go` as the
"platform services" bucket; NAT/screen/zones/applications land in
`types_security.go` as the security-policy bucket. The exact bucket of a
borderline type (e.g. `FirewallConfig` vs security) is a reviewer
question (§11 Q4) — it does not affect correctness, only cohesion.

## 4. Mechanical method — byte-identical motion

Each type/const/var/method block is **cut verbatim** (including its leading
doc comment, preserving exact whitespace and blank-line separators) from
`types.go` and pasted into the target sibling file. No identifier renames,
no signature changes, no reordering of fields. Every new file gets the
identical header:

```go
package config

import (
	"fmt"
	"strconv"
	"strings"
)
```

…then `goimports`/`gofmt` prunes unused imports per file (most domain
files will need 0–2 of those three; `types_system.go`'s `RPMTest.Effective*`
methods use neither `fmt` nor `strconv` — they're pure field-or-default
returns, so that file likely needs no imports at all). Running `gofmt -l`
and `go vet` after each extraction is the correctness check.

The kept `types.go` retains `fmt`/`strconv`/`strings` (the resolution
helpers use all three).

## 5. Public API preservation

**Zero public-API change.** Every exported identifier
(`config.SecurityConfig`, `config.NATType`, `config.PermAll`,
`config.LoginClassPermissions`, `(*config.Config).TunnelNameMap`, …) keeps
its exact name, package qualifier, and signature. They simply live in a
different file of the same package. Go has no file-level visibility — a
same-package split is invisible to every one of the 194 consumers. `go
build ./...` across all consumers is the proof obligation (§9).

## 6. Hidden invariants the change must preserve

1. **No import cycle.** Same-package motion adds no import edge. The only
   risk is a *new external import* pulled into a domain file — but we add
   none; we only redistribute `fmt`/`strconv`/`strings` already present.
2. **No duplicate-symbol / missing-symbol.** Every block moves exactly
   once. Verified by `go build` (duplicate → redeclaration error; missing
   → undefined error) plus a pre/post `grep -c "^type \|^func \|^const \|^var "`
   symbol-count reconciliation.
3. **`iota` block integrity.** The three `const ( … iota )` blocks
   (`LoginClassPermission`, `PolicyAction`, `NATType`) MUST move as intact
   units with their owning type — splitting an `iota` block changes the
   ordinal values. Each stays adjacent to its type in one domain file.
4. **`LoginClassPermissions` var depends on the `Perm*` consts** — both
   move together into `types_system.go`.
5. **`Default*RPM*` const block** is referenced by the `RPMTest.Effective*`
   methods — both move together into `types_system.go`.
6. **gofmt/vet clean** — the tree must be `gofmt`-clean and `go vet`-clean
   after the split, exactly as before.

## 7. Risk assessment

| Class | Level | Rationale |
|-------|-------|-----------|
| Behavioral regression | **LOW** | Pure file motion; compiled output identical. No logic touched. |
| Lifetime / borrow-checker | **N/A** | Go, not Rust. No ownership concerns. |
| Performance regression | **NONE** | Same package, same compiled binary. |
| Architectural mismatch (#961/#946-P2 dead-end) | **LOW** | Issue explicitly proposes this split and names the domains; #1699 just proved the same-package motion approach on the sibling file. The only architectural trap (sub-package → cycle/churn) is explicitly avoided in §3. |
| Import cycle | **NONE** | No new import edges; same-package. |
| Consumer API churn | **NONE** | §5 — file-level split is invisible to importers. |

## 8. Why NOT a sub-package (the central #1701 risk, answered)

The issue's PLAN-KILL trigger is "types don't decompose without breaking
the consumer API or creating cycles." A sub-package **would** break the
consumer API (194 files import `config.Foo`) and **could** create cycles
(the `config` package's parser/AST/compiler/schema files both consume and
construct these types; a `config/types` sub-package referenced by
`config` is fine, but the moment a type method or the schema layer needs
something from `config`, the edge reverses → cycle). Same-package sibling
files sidestep both: chosen because it is the only decomposition that
satisfies the issue's own kill criteria. This is the load-bearing decision
for the whole plan.

## 9. Test plan (control-plane config — NO cluster smoke)

This is a Go control-plane refactor with no dataplane/Rust/cluster surface.
Per the task's gate definition, the gate is:

- [ ] `gofmt -l pkg/config/` clean (no listed files).
- [ ] `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go build ./...` clean —
      ALL consumers, proving zero API churn.
- [ ] `go vet ./pkg/config/...` (and full `go vet ./...`) clean.
- [ ] `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` —
      full Go suite passes. Pre-existing `pkg/dataplane/userspace` sandbox
      unix-socket test failures are known artifacts; reproduce them on
      clean `origin/master` FIRST and prove they are pre-existing (not
      introduced by this PR) per the no-test-dismissal rule.
- [ ] Symbol-count reconciliation: `grep -c` of `^type `/`^func `/`^const `/
      `^var ` across the new file set equals the pre-split count in the
      original `types.go`.
- [ ] `make audit-check` PASSES after regenerating
      `docs/refactoring-audit-current.txt` (regen done LAST, post-rebase
      onto current master, to avoid the #1671 parallel-refactor audit-drift
      race).

No cluster smoke: the change cannot affect the dataplane fast path, CoS
classifier, or TX path — it is type definitions only, byte-identical after
compilation.

## 10. Out of scope (explicitly)

- Renaming/reorganizing types, fields, or methods.
- Moving methods to be defined nearer their compiler/parser usage.
- Touching `compiler_*.go`, `parser_*.go`, `schema*.go`, `ast*.go`.
- Any sub-package extraction (rejected, §8).
- Splitting `predefined.go`, `value_type.go`, or other already-small files.

## 11. Open questions for adversarial review

1. **Is same-package sibling motion the right call vs a sub-package?**
   §3/§8 argue sub-package is killable on the issue's own criteria. Is
   there a sub-package shape that avoids both the 194-file churn and the
   cycle risk that I've missed (e.g. a leaf `config/model` with type
   aliases)? If yes and it's cleaner, that may be the better plan — or this
   may be a reason to KILL in favor of a different decomposition.
2. **`iota`/`var`/`const` co-motion** — have I correctly identified ALL
   ordinal-sensitive blocks (`LoginClassPermission`, `PolicyAction`,
   `NATType`) and value-dependency pairs (`LoginClassPermissions`↔`Perm*`,
   `Default*RPM*`↔`RPMTest.Effective*`)? A missed dependency split across
   files still compiles but could change an `iota` ordinal — would a
   reviewer catch a silent ordinal shift? (Answer: ordinal shift only if a
   block is *internally* split; moving an intact block preserves ordinals.
   Confirm the audit covers "no const block is internally split.")
3. **Does the per-file import pruning risk a wrong prune?** `goimports`
   could in principle keep an import that's only used in another file if I
   paste the wrong block. Is `go vet` + `gofmt -l` + `go build` sufficient
   to catch every such case, or is a stricter check warranted?
4. **Domain bucket cohesion** — is putting `FirewallConfig`/filters,
   `ServicesConfig`, `ForwardingOptionsConfig`, and DHCP-server in
   `types_system.go` defensible, or should `FirewallConfig` join
   `types_security.go`? This is cohesion-only (no correctness impact) but
   affects the refactor's value.
5. **Is the maintainability win worth the churn at all?** A 2055-LOC
   type-only file with no logic is arguably already navigable via IDE
   symbol index. Is this churn (7 files, git-blame disruption on every
   type) justified, or is PLAN-KILL the honest call? The repo's modularity
   discipline (`docs/engineering-style.md`, files > ~2000 LOC) is the
   pro-split argument; weigh it.
6. **Git-blame / bisect impact** — the merge-commit policy preserves
   per-file-extraction commits, but `git blame` on any moved type now
   points at the extraction commit, not the original author. Is that an
   acceptable cost (it was for #1699)?
