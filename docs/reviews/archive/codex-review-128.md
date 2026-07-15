# Codex Review Audit 128 - Core Firewall Policy Diagnostics and Host-Inbound Parity

Agent: codex  
Checkout: `/home/ps/git/codex-bpfrx`  
Commit inspected: `6b588b715`  
Date: 2026-07-01  
Focus: core firewall behavior, especially zone policy diagnostics, host-inbound enforcement, app/protocol selectors, default deny/permit behavior, and vSRX parity.

## Procedure

- Ran `git pull --rebase`; result: already up to date.
- Selected `/tmp/codex-review-128.md` because `/tmp/agy-review-128.md` exists and `/tmp/codex-review-128.md` did not.
- Read prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` for duplicate suppression, with special attention to the latest `codex-review-127.md` and `agy-review-128.md`.
- Read recent repository docs/issues/backlog content through local `.md` files and grep results rather than using `gh`.
- Inspected the policy simulator, local CLI, remote CLI, gRPC text bridge, typed gRPC match-policies API, REST match-policies API, kernel nft host-inbound mirror, Rust AF_XDP host-inbound path, application/protocol validation, and related tests.

## Duplicate Suppression

Not re-reported because they already appear in prior reports or recent issue/PR history:

- Signed numeric policy selector drift such as `+80` / `+8` in diagnostic parsers.
- REST/CLI canonical unsigned parser drift fixed by the recent `ParseCanonicalUint` work.
- Unknown/global host-inbound zone ID admit-all.
- VLAN logical-ifindex per-interface host-inbound override miss.
- Missing implicit `junos-host` default deny, `to-zone any`, and wildcard host-inbound paths.
- `system-services all` full-packet admission.
- Per-interface host-inbound display/API/proto drift already tracked in prior 123/125 reports.
- Policy ID/scope/display drift around the #3658-#3685 cluster now fixed on master.
- Intrazone default/precedence findings from earlier reviews.
- AppID/DPI, UTM/AppSecure/SecIntel, reject profiles, IP reassembly, and other already-open feature-gap items.

## Module Checklist

1. Prior audit reports and local issue docs: inspected for duplicates.
2. Local CLI `show security match-policies`: inspected parser and tests.
3. Local CLI `test policy`: inspected parser and tests.
4. Remote CLI `show security match-policies`: inspected parser and tests.
5. Remote CLI `test policy`: inspected parser, topic builder, and tests.
6. gRPC `ShowText` `test-policy:` bridge: inspected topic parser and tests.
7. gRPC typed `MatchPolicies`: inspected validation path; negative result for this round.
8. REST `match-policies`: inspected through grep/docs/tests; negative result for this round.
9. Shared `pkg/policymatch`: inspected validation helpers, usage strings, and test coverage.
10. Kernel nft host-inbound mirror: inspected ESP/AH bypass and `ident-reset`.
11. Rust AF_XDP host-inbound classifier/build state: inspected token handling and comments.
12. Application/protocol validation: inspected current canonical behavior; no fresh high-confidence bug.

## Negative Results

- The typed gRPC `MatchPolicies` RPC now rejects missing zones, malformed IPs, invalid ports, and invalid protocols before evaluation (`pkg/grpcapi/server_cluster.go:142-175`). I did not find a fresh typed-RPC fail-open in this pass.
- The REST match-policies handler appears to have already absorbed the recent canonical parser fixes; I did not find a fresh non-duplicate REST selector drift in this pass.
- `appid.ProtocolNumber` accepts some numeric spelling the Rust side would not parse directly, but the userspace capability compiler canonicalizes accepted numeric protocols before sending them downstream. I did not keep this as a finding.
- Global policy/default-policy display and ID/scope fields have extensive recent fixes and tests. I did not find a fresh non-duplicate issue there in this pass.

## High Confidence Findings

### H01 - Local `show security match-policies` silently widens a query when a selector is missing its value

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `cli`, `test-gap`

Evidence:
- `pkg/cli/cli_show_security.go:358-423` loops over tokens and each known selector only consumes a value when `i+1 < len(args)`.
- There is no `else` error for `source-port`, `destination-port`, `protocol`, `icmp-type`, `icmp-code`, `source-ip`, or `destination-ip`.
- `pkg/policymatch/policymatch.go:84-88` documents why silently dropping a bad port selector widens to wildcard and yields a verdict for traffic the operator did not describe.

Runtime trace:
- Operator runs local `show security match-policies from-zone trust to-zone untrust destination-port`.
- The parser sees `destination-port`, finds no following value, and leaves `dstPort == 0`.
- `0` means wildcard, so the simulator evaluates all destination ports instead of failing the malformed command.

Why it matters:
- This is a firewall diagnostic tool. A missing selector value should be a command error, not a broader query. Operators can read a false permit/deny verdict while debugging zone policy.

Fix direction:
- Add a shared `takeValue` helper like `cmd/cli/show.go:775-783` uses for session filters.
- Return `missing value for "destination-port"` and equivalent errors for every value-taking selector.
- Add local CLI tests for trailing selector tokens.

### H02 - Local `show security match-policies` ignores unknown selector tokens

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `cli`, `test-gap`

Evidence:
- `pkg/cli/cli_show_security.go:358-423` has a `switch args[i]` with no `default` error case.
- `cmd/cli/show.go:766-783` shows the stricter pattern already used for another firewall diagnostic parser: unknown or malformed tokens are surfaced rather than ignored.

Runtime trace:
- Operator mistypes `destination-poort 443`.
- The parser ignores `destination-poort`, then ignores/continues over `443` as an unknown token.
- The query runs without a destination-port constraint.

Why it matters:
- Typoed selectors silently become wildcard selectors. This is the same class of false-positive firewall simulation that earlier port/protocol fixes were trying to eliminate.

Fix direction:
- Add a `default` case returning `unknown selector %q`.
- Cover misspelled selector tokens in tests.

### H03 - Local `test policy` silently widens a query when a selector is missing its value

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `cli`, `test-policy`

Evidence:
- `pkg/cli/cli_request.go:184-255` uses the same `if i+1 < len(args)` pattern with no missing-value error.
- The parser handles `source-port`, `destination-port`, `protocol`, `icmp-type`, and `icmp-code`, but only validates values if a value exists.

Runtime trace:
- Operator runs `test policy from-zone trust to-zone untrust source-port`.
- `srcPort` remains `0`, which is the wildcard.
- The command reports a policy result for any source port.

Why it matters:
- `test policy` is a core vSRX-style operational command. Fail-open parsing makes policy validation less trustworthy during incident response.

Fix direction:
- Use the same strict selector parser as `show security match-policies`.
- Add missing-value table cases for each selector.

### H04 - Local `test policy` ignores unknown selector tokens

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `cli`, `test-policy`

Evidence:
- `pkg/cli/cli_request.go:184-255` has no `default` switch arm.
- Usage text at `pkg/policymatch/policymatch.go:205-215` lists accepted selectors, but the parser does not reject tokens outside that grammar.

Runtime trace:
- Operator runs `test policy from-zone trust to-zone untrust protcol tcp`.
- The typo `protcol` and value `tcp` are both ignored.
- `proto == ""`, which is the unspecified wildcard.

Why it matters:
- A typo in the protocol dimension can turn a TCP-only diagnostic into an any-protocol diagnostic.

Fix direction:
- Reject unknown selector tokens and add tests for spelling errors.

### H05 - Remote CLI `show security match-policies` silently widens a query when a selector is missing its value

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `remote-cli`, `grpc`

Evidence:
- `cmd/cli/show.go:1174-1255` repeats the optional `if i+1 < len(args)` pattern.
- The same file contains a hardened session parser at `cmd/cli/show.go:766-783`, including an explicit missing-value error.

Runtime trace:
- Remote operator runs `cli show security match-policies from-zone trust to-zone untrust protocol`.
- `req.Protocol` remains empty.
- The remote client sends a broader `MatchPoliciesRequest` than the command text describes.

Why it matters:
- Remote CLI is likely the normal operational path. It should not be weaker than the typed gRPC handler it feeds.

Fix direction:
- Reuse a common selector parser between local and remote match-policies surfaces.
- Assert that no RPC is issued when parsing fails.

### H06 - Remote CLI `show security match-policies` ignores unknown selector tokens

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `remote-cli`, `grpc`

Evidence:
- `cmd/cli/show.go:1174-1255` has no `default` case.
- Existing remote tests at `cmd/cli/show_matchpolicies_port_3354_test.go:21-49` cover malformed numeric values and assert no RPC, but they do not cover unknown selector tokens.

Runtime trace:
- Operator runs `cli show security match-policies from-zone trust to-zone untrust destination-poort 443`.
- The typo is ignored, and `DestinationPort` remains zero.
- `MatchPolicies` RPC evaluates all destination ports.

Why it matters:
- This can produce a misleading policy match for a packet with an unparsed destination port.

Fix direction:
- Add a `default` error and a fake-client test that `MatchPolicies` is not called for unknown selectors.

### H07 - Remote CLI `test policy` silently widens a query when a selector is missing its value

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `remote-cli`, `test-policy`

Evidence:
- `cmd/cli/main.go:447-523` repeats the missing-value pattern.
- `cmd/cli/main.go:540-562` then serializes only non-zero/non-empty selectors into a `test-policy:` topic.

Runtime trace:
- Operator runs `cli test policy from-zone trust to-zone untrust icmp-type`.
- `icmpType` stays nil.
- Topic string lacks `ictype=`, so the backend evaluates all ICMP types.

Why it matters:
- ICMP type/code matching was recently added because type-constrained applications matter. The outer parser still allows malformed type selectors to disappear.

Fix direction:
- Fail before building the topic when a selector lacks a value.
- Add missing-value tests for `icmp-type` and `icmp-code`.

### H08 - Remote CLI `test policy` ignores unknown selector tokens

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `remote-cli`, `test-policy`

Evidence:
- `cmd/cli/main.go:447-523` has no `default` case.
- `cmd/cli/testpolicy_protocol_test.go:21-40` covers invalid protocol values, but not unknown selector keys.

Runtime trace:
- Operator runs `cli test policy from-zone trust to-zone untrust proto tcp`.
- The accepted selector is `protocol`, not `proto`; `proto tcp` is ignored at the CLI layer.
- Backend receives no protocol constraint.

Why it matters:
- The backend topic parser uses `proto=`, while the CLI grammar uses `protocol`. This makes a plausible operator shorthand especially dangerous because it is silently accepted as nothing.

Fix direction:
- Reject unknown tokens and include a diagnostic that points to `protocol`.

### H09 - gRPC `ShowText` `test-policy:` silently ignores malformed `key=value` segments

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `grpc`, `test-policy`

Evidence:
- `pkg/grpcapi/server_show_firewall.go:180-184` splits each comma segment on `=` and `continue`s when `len(parts) != 2`.
- The rest of the handler validates only keys that survive this parse.

Runtime trace:
- A caller sends `ShowText{Topic:"test-policy:from=trust,to=untrust,port"}`.
- The `port` segment is skipped.
- `dstPort` remains zero and the simulator evaluates all destination ports.

Why it matters:
- Even if the current remote CLI is the main producer, this is still a public server-side text command boundary. The server should reject malformed topic grammar, not reinterpret it as wildcard.

Fix direction:
- Return a diagnostic for malformed segments.
- Add `ShowText` tests for `port`, `proto`, and other missing-`=` tokens.

### H10 - gRPC `ShowText` `test-policy:` silently ignores unknown keys

Severity: High  
Confidence: High  
Labels: `bug`, `security`, `firewall-policy`, `grpc`, `test-policy`

Evidence:
- `pkg/grpcapi/server_show_firewall.go:185-225` switches on known keys and has no `default` case.
- Existing tests at `pkg/grpcapi/server_proto_validation_test.go:74-90` cover invalid `proto=` values, but not misspelled keys.

Runtime trace:
- A caller sends `test-policy:from=trust,to=untrust,prot=tcp`.
- `prot` is ignored.
- `proto` remains empty, which `policymatch.ValidateProtocol` treats as wildcard.

Why it matters:
- The gRPC text bridge is the backend for remote `test policy`. A misspelled selector should fail closed at the parser boundary.

Fix direction:
- Add a `default` branch that records an invalid-key error and prints a diagnostic before simulation.

## Medium Confidence Findings

### M01 - gRPC `ShowText` treats explicit empty typed selector values as wildcard

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `firewall-policy`, `grpc`, `test-policy`

Evidence:
- `pkg/grpcapi/server_show_firewall.go:194-224` calls `ParsePort`, `ValidateProtocol`, and `ParseICMPValue` on topic values.
- `pkg/policymatch/policymatch.go:110-114`, `139-143`, and `176-178` all treat empty/whitespace values as unspecified wildcard.

Runtime trace:
- A caller sends `test-policy:from=trust,to=untrust,port=`.
- `ParsePort("")` returns `(0, nil)`.
- The handler evaluates all destination ports.

Why it matters:
- Empty value is fine for an omitted selector, but an explicit `port=` segment is malformed command input. Treating it as omitted hides operator or producer bugs.

Fix direction:
- Distinguish "key absent" from "key present with empty value" in the text bridge.
- Keep typed gRPC scalar zero behavior unchanged; this is only about textual topic grammar.

### M02 - Addressless configured zones have a host-inbound admit window until an address appears

Severity: Medium  
Confidence: Medium  
Labels: `security`, `host-inbound`, `vsrx-parity`, `firewall-policy`

Evidence:
- `pkg/dataplane/userspace/zones.go:84-92` explicitly says a configured zone whose interfaces have no static or live kernel address yields an empty address set, the daemon emits no deny for it, and it self-heals once an address appears.

Runtime trace:
- DHCP WAN zone is configured with no host-inbound stanza.
- Before the first lease appears, no scoped nft deny is emitted for the zone address.
- If the address is usable before the lease-change reconcile completes, host-bound packets can hit the kernel input path without the intended zone default-deny.

Why it matters:
- vSRX-style host-inbound default deny is an enforcement invariant, not only a steady-state property. DHCP, VIP, and failover windows are exactly where security appliances get probed.

Fix direction:
- Consider fail-closed interface-scoped nft rules during addressless windows where possible.
- At minimum, add explicit tests and event-log warnings for configured-but-addressless enforcing zones.

### M03 - Kernel host-inbound globally accepts raw ESP/AH before per-zone policy

Severity: Medium  
Confidence: Medium  
Labels: `security`, `ipsec`, `host-inbound`, `vsrx-parity`

Evidence:
- `pkg/daemon/daemon_nft.go:380-392` adds `meta l4proto { 50, 51 } accept` before zone-scoped host-inbound drops.
- `userspace-dp/src/afxdp/forwarding/host_inbound.rs:145-153` maps `ike`/`ipsec` tokens to UDP 500/4500 while comments say raw ESP/AH is handled before host-inbound.

Runtime trace:
- Any interface with the kernel host-inbound nft chain receives raw ESP/AH.
- The rule accepts ESP/AH regardless of whether that zone configured `ike`, `ipsec`, or any host-inbound stanza.

Why it matters:
- The code comment explains this as necessary for XFRM, but vSRX host-inbound posture is normally zone-scoped. A global raw-protocol accept is a broader attack surface than "IPsec enabled on this external zone".

Fix direction:
- Scope ESP/AH accept to zones/interfaces that are configured for IPsec, or document and test the intentional global exception.
- Add parity tests showing ESP/AH behavior for an IPsec zone and a non-IPsec zone.

### M04 - AF_XDP `ident-reset` drops instead of resetting on the secondary host-inbound path

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `host-inbound`, `vsrx-parity`, `userspace-dataplane`

Evidence:
- Kernel nft maps `ident-reset` to `reject with tcp reset` at `pkg/daemon/daemon_nft.go:495-527`.
- AF_XDP explicitly contributes no admit rule for `ident-reset` at `userspace-dp/src/afxdp/forwarding/host_inbound.rs:167-183`, and comments call it a documented divergence.

Runtime trace:
- Direct host-bound TCP/113 usually hits the kernel and gets a TCP RST.
- Edge paths such as DNAT/static-NAT-to-113 that reach AF_XDP local-delivery instead silently drop.

Why it matters:
- vSRX `ident-reset` semantics are active reset, not silent drop. The current split means behavior depends on which local-delivery path a packet takes.

Fix direction:
- Implement a secondary-path RST action for `ident-reset`, or add an explicit issue and smoke test documenting the accepted divergence.

### M05 - Per-interface host-inbound "override" is implemented as union, so it cannot narrow zone-level permits

Severity: Medium  
Confidence: Medium  
Labels: `security`, `host-inbound`, `vsrx-parity`, `configuration-semantics`

Evidence:
- `pkg/dataplane/userspace/zones.go:103-108` says the effective token set is the union of zone-level and interface override tokens.
- `userspace-dp/src/afxdp/forwarding_build/interfaces.rs:93-99` repeats "zone union interface" and calls it an override.

Runtime trace:
- Zone allows `ssh`.
- Interface stanza is configured empty or with only `ping` to narrow exposure.
- Effective set remains at least the zone-level permit set, so `ssh` stays allowed on that interface.

Why it matters:
- The word "override" implies an interface can narrow a broad zone default. If operators expect Junos/vSRX-style per-interface host-inbound precision, union semantics can leave services exposed.

Fix direction:
- Confirm intended semantics against vSRX.
- If narrowing is desired, compile interface stanzas as replace/override, not union.
- If union is intentional, rename docs/UI from override to additive exception and add tests proving broad zone permits remain active.

### M06 - Rust hot-path comments still describe obsolete no-stanza admit-all semantics

Severity: Medium  
Confidence: Medium  
Labels: `documentation`, `host-inbound`, `maintainability`

Evidence:
- `userspace-dp/src/afxdp/forwarding_build/zones.rs:45-47` says zones without a stanza are left absent and admit-all.
- `userspace-dp/src/afxdp/types/forwarding.rs:200-205` says `ForwardingState` only holds `ZoneHostInbound` for zones that declared a stanza and absent means admit-all.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1819-1820` repeats that a zone with no host-inbound stanza admits everything.

Runtime trace:
- The control plane now marks configured zones enforcing to get default-deny behavior.
- A future dataplane engineer reading these comments could preserve the wrong absence semantics or reintroduce admit-all on a refactor.

Why it matters:
- This is firewall hot-path documentation. Wrong comments around fail-open/fail-closed semantics are operational risk, especially after the eBPF/userspace transition.

Fix direction:
- Update comments to distinguish legacy snapshots from current control-plane generated snapshots.
- Add a short invariant comment: current configs produce enforcing entries for every configured zone; absence is legacy/unconfigured only.

### M07 - Four policy diagnostic parsers duplicate grammar instead of sharing a strict parser

Severity: Medium  
Confidence: High  
Labels: `refactor`, `modularity`, `firewall-policy`, `cli`

Evidence:
- Local show parser: `pkg/cli/cli_show_security.go:358-423`.
- Local test parser: `pkg/cli/cli_request.go:184-255`.
- Remote show parser: `cmd/cli/show.go:1174-1255`.
- Remote test parser: `cmd/cli/main.go:447-523`.
- Shared usage exists at `pkg/policymatch/policymatch.go:186-224`, but parsing is still duplicated.

Runtime trace:
- Every new selector or validation rule must be patched into four loops.
- Prior history already shows parser drift: comments in `pkg/policymatch/policymatch.go:192-200` describe hidden selectors and drifted help.

Why it matters:
- Diagnostic correctness is security-relevant. Hand-maintained parser copies are why these missing-value/unknown-token failures survive after numeric value validation was fixed.

Fix direction:
- Move selector parsing into `pkg/policymatch`, returning a `Query` plus rendering options.
- Have local and remote CLIs call the same parser.

### M08 - Help text advertises allowed selectors but not strict failure behavior

Severity: Medium  
Confidence: Medium  
Labels: `documentation`, `cli`, `firewall-policy`

Evidence:
- `pkg/policymatch/policymatch.go:205-215` lists selector syntax and says omitted selectors match any.
- It does not state that unknown selectors or present-without-value selectors are errors, because the current implementation does not enforce that.

Runtime trace:
- After parser hardening, operators should see consistent grammar errors.
- Without help text updates, there will be ambiguity between "omitted" and "present but empty/malformed".

Why it matters:
- Firewall diagnostic commands need predictable grammar. "Omitted matches any" must not be confused with "typoed or empty selector matches any".

Fix direction:
- After strict parsing lands, extend usage with a concise note: omitted selectors match any; unknown selectors and missing values are errors.

### M09 - Remote `test policy` topic serialization has no structured encoding boundary

Severity: Medium  
Confidence: Medium  
Labels: `refactor`, `grpc`, `firewall-policy`, `test-policy`

Evidence:
- `cmd/cli/main.go:540-562` concatenates a comma-separated `test-policy:` topic string.
- `pkg/grpcapi/server_show_firewall.go:180-225` reparses the string manually.

Runtime trace:
- The remote CLI converts structured argv into an ad hoc string.
- The server reparses that ad hoc string into structured fields.
- Parser bugs at either end can silently widen or drop selectors.

Why it matters:
- There is already a typed `MatchPolicies` RPC. The text topic format is unnecessary for a security-sensitive operational command and has caused repeated parser drift.

Fix direction:
- Route remote `test policy` through typed `MatchPolicies` or add a typed `TestPolicy` RPC.
- Keep `ShowText` only as compatibility glue with strict parser tests.

### M10 - gRPC `ShowText` malformed topic tests cover invalid values but not malformed grammar

Severity: Medium  
Confidence: High  
Labels: `test-gap`, `grpc`, `firewall-policy`

Evidence:
- `pkg/grpcapi/server_proto_validation_test.go:74-90` covers invalid protocol values like `notaproto`, `tcpp`, and `999`.
- It does not cover malformed segments (`port`), unknown keys (`prot=tcp`), or explicit empty values (`port=`).

Runtime trace:
- Removing the `len(parts) != 2 { continue }` behavior would not currently be pinned by tests.
- Adding a typoed key test would fail today.

Why it matters:
- The value validators are only useful if the outer grammar parser invokes them.

Fix direction:
- Add red-on-revert tests for malformed segment, unknown key, and empty typed value.

### M11 - Local policy diagnostic tests cover invalid values but not outer grammar

Severity: Medium  
Confidence: High  
Labels: `test-gap`, `cli`, `firewall-policy`

Evidence:
- `pkg/cli/policymatch_port_test.go:76-114` covers malformed/out-of-range port values and the absent-selector case.
- `pkg/cli/testpolicy_srcport_test.go:108-125` covers malformed/out-of-range source-port values.
- Neither test covers trailing selector tokens or unknown selector names.

Runtime trace:
- `destination-port abc` fails as intended.
- `destination-port` silently widens and remains untested.
- `destination-poort 443` silently widens and remains untested.

Why it matters:
- This is the exact outer-layer bug class left after value validation hardening.

Fix direction:
- Add local CLI table cases for every selector and at least one unknown token per command.

### M12 - Remote policy diagnostic tests cover invalid values but not outer grammar

Severity: Medium  
Confidence: High  
Labels: `test-gap`, `remote-cli`, `firewall-policy`

Evidence:
- `cmd/cli/show_matchpolicies_port_3354_test.go:21-49` covers invalid port values and asserts no RPC.
- `cmd/cli/testpolicy_protocol_test.go:21-40` covers invalid protocol values.
- Neither covers missing selector values or unknown selector names.

Runtime trace:
- `destination-port abc` returns an error before RPC.
- `destination-port` sends a wildcard RPC.
- `destination-poort 443` sends a wildcard RPC.

Why it matters:
- The remote CLI is likely the normal operational interface. It needs fake-client tests proving malformed input never reaches the backend.

Fix direction:
- Mirror the existing invalid-value no-RPC tests for missing and unknown tokens.

## Low Confidence Findings

### L01 - `ident-reset` divergence needs an explicit vSRX parity issue if not fixed

Severity: Low  
Confidence: Medium  
Labels: `vsrx-parity`, `host-inbound`, `documentation`

Evidence:
- `userspace-dp/src/afxdp/forwarding/host_inbound.rs:167-183` documents the AF_XDP drop behavior as a divergence and says a future secondary-path RST upgrade has an obvious home.

Runtime trace:
- Most traffic gets kernel reset semantics.
- Edge local-delivery paths get silent drop semantics.

Why it matters:
- Even if acceptable, this should be a tracked parity decision so future reviews do not keep rediscovering it.

Fix direction:
- File or link an issue labeled `vsrx-parity` and add a regression test for the chosen behavior.

### L02 - Addressless host-inbound windows need observability even if accepted

Severity: Low  
Confidence: Medium  
Labels: `observability`, `host-inbound`, `security`

Evidence:
- `pkg/dataplane/userspace/zones.go:88-92` acknowledges no deny is emitted until an address appears.

Runtime trace:
- On DHCP/VIP bootstrap, the system may temporarily have no enforceable scoped host-inbound view.
- Operators get no obvious warning in the cited code path.

Why it matters:
- Fail-open windows should be visible in logs/metrics even when they self-heal.

Fix direction:
- Emit a warning or counter for configured enforcing zones omitted due to empty address sets.

### L03 - ESP/AH global bypass needs an explicit negative test on a non-IPsec zone

Severity: Low  
Confidence: Medium  
Labels: `test-gap`, `ipsec`, `host-inbound`, `vsrx-parity`

Evidence:
- `pkg/daemon/daemon_nft.go:380-392` installs the global raw ESP/AH accept.

Runtime trace:
- A non-IPsec WAN-like zone still gets raw ESP/AH accepted by the kernel input chain.

Why it matters:
- If the global exception is intentional, tests should prove the design choice and stop future ambiguity.

Fix direction:
- Add nft payload/render tests for IPsec and non-IPsec zones and document the expected accept/drop semantics.

### L04 - The match-policies usage SSOT is not matched by a parser SSOT

Severity: Low  
Confidence: High  
Labels: `refactor`, `modularity`, `cli`

Evidence:
- Usage is centralized in `pkg/policymatch/policymatch.go:186-224`.
- Parsing remains distributed across four command files.

Runtime trace:
- The docs can be correct while individual parsers stay drifted.

Why it matters:
- Centralized help without centralized parsing only solves half the drift problem.

Fix direction:
- Introduce a `policymatch.ParseSelectorArgs(args []string) (Query, error)` primitive.

### L05 - The local and remote parser comments still focus on old value-coercion bugs, not full grammar strictness

Severity: Low  
Confidence: High  
Labels: `documentation`, `cli`, `maintainability`

Evidence:
- Comments in `pkg/cli/cli_request.go:209-214`, `cmd/cli/main.go:472-490`, and `cmd/cli/show.go:1201-1205` explain invalid numeric coercion.
- They do not mention that the surrounding parser can skip validation entirely for missing values.

Runtime trace:
- A maintainer sees `ParsePort` and assumes the surface is safe.
- The parser never calls `ParsePort` for a trailing selector.

Why it matters:
- Comments document the fixed inner-layer bug while hiding the unfixed outer-layer bug.

Fix direction:
- Once strict parsing is in place, update comments to state that selector presence always requires a value and unknown selectors are rejected.

### L06 - `ShowText` text grammar duplicates typed `MatchPolicies` validation and should be retired or quarantined

Severity: Low  
Confidence: Medium  
Labels: `refactor`, `grpc`, `security`

Evidence:
- Typed validation lives in `pkg/grpcapi/server_cluster.go:142-175`.
- Text parsing lives separately in `pkg/grpcapi/server_show_firewall.go:180-225`.

Runtime trace:
- The typed RPC has structured fields and validation.
- The text RPC has string grammar and drift-prone parsing.

Why it matters:
- Firewall simulation should prefer structured APIs. Keeping two validation front doors multiplies security review work.

Fix direction:
- Have `showTestPolicy` translate into a `MatchPoliciesRequest` using a shared strict parser and then call the typed implementation.

### L07 - Host-inbound semantics are spread across Go compiler, nft renderer, Rust builder, and Rust hot path

Severity: Low  
Confidence: Medium  
Labels: `refactor`, `modularity`, `host-inbound`, `userspace-dataplane`

Evidence:
- Go view construction: `pkg/dataplane/userspace/zones.go:93-112`.
- nft rendering and special cases: `pkg/daemon/daemon_nft.go:377-392`, `495-527`.
- Rust build comments/state: `userspace-dp/src/afxdp/forwarding_build/zones.rs:45-52`, `interfaces.rs:93-104`.
- Rust hot path comments: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1814-1823`.

Runtime trace:
- One semantic change, such as no-stanza default-deny, must be reflected in several places.
- Several comments already disagree with current behavior.

Why it matters:
- Host-inbound is a security boundary. Its invariants should be mechanically centralized as much as possible.

Fix direction:
- Create a host-inbound module package with explicit invariants and generated/validated parity tests across Go nft and Rust userspace paths.

### L08 - No explicit negative result documenting that REST/gRPC typed match-policies are now stricter than CLI grammar

Severity: Low  
Confidence: Medium  
Labels: `documentation`, `test-gap`, `firewall-policy`

Evidence:
- `pkg/grpcapi/server_cluster.go:142-175` has strict typed validation.
- CLI/parser surfaces above remain permissive on missing/unknown tokens.

Runtime trace:
- The same conceptual diagnostic is strict when invoked as typed gRPC but permissive through operator CLI argv.

Why it matters:
- Inconsistent strictness makes it harder to know which diagnostic surface is authoritative during reviews.

Fix direction:
- Add README notes and tests that define a single parser contract for every surface.

### L09 - Current tests do not exercise "present but empty" selectors as distinct from omitted selectors

Severity: Low  
Confidence: High  
Labels: `test-gap`, `firewall-policy`, `cli`, `grpc`

Evidence:
- `pkg/policymatch/policymatch.go:96-103`, `125-133`, and `155-169` intentionally treat empty helper inputs as unspecified.
- Command-level tests cover omitted selectors as legitimate wildcard cases, but not explicit empty selector syntax like `port=`.

Runtime trace:
- Omitted `destination-port` should mean wildcard.
- Explicit empty `destination-port ""` or `port=` should probably be an input error at command grammar level.

Why it matters:
- Helper-level semantics are right for typed optional fields, but command parsers need to preserve the difference between omitted and malformed.

Fix direction:
- Add command-level tests that reject explicit empty values while leaving omitted selectors valid.

### L10 - The review found no fresh dataplane packet-classifier deny/permit bug, but the diagnostic command gap can hide one

Severity: Low  
Confidence: Medium  
Labels: `operational-risk`, `firewall-policy`, `test-gap`

Evidence:
- Policy simulator values ultimately flow into `pkg/policymatch`, which is shared by REST/gRPC/CLI diagnostics.
- The parser issues above can cause diagnostics to evaluate a different packet than the operator requested.

Runtime trace:
- Packet is denied in dataplane for TCP/443.
- Operator typo drops `destination-port 443` and simulator evaluates "any port"; a different permit rule may match.

Why it matters:
- A correct dataplane is not enough if the primary validation/debug tools silently answer a different question.

Fix direction:
- Treat parser hardening as part of firewall correctness, not just CLI polish.

## Suggested First Fix Batch

1. Add `policymatch.ParseSelectorArgs(args []string) (Query, error)` with strict missing-value and unknown-token handling.
2. Convert all four CLI surfaces to the shared parser.
3. Add no-RPC tests for remote CLI parse errors.
4. Harden `ShowText` `test-policy:` parser against malformed segments, unknown keys, and explicit empty typed values.
5. Update host-inbound comments that still say no-stanza admit-all.
6. Decide whether ESP/AH global accept, AF_XDP `ident-reset` drop, per-interface union semantics, and addressless enforcement windows are intentional. If intentional, file/link `vsrx-parity` or security-semantics issues and pin with tests.

## Commands Run

- `git pull --rebase`
- `git status --short`
- `git rev-parse --short HEAD`
- `rg`/`nl` inspections over `pkg/cli`, `cmd/cli`, `pkg/grpcapi`, `pkg/policymatch`, `pkg/dataplane/userspace`, `pkg/daemon`, and `userspace-dp/src/afxdp`.
- Previously during this audit window:
  - `go test ./pkg/appid ./pkg/config -run 'TestProtocolNumberNumericAndProtocolZero|TestApplicationProtocol' -count=1`
  - `go test ./pkg/policymatch -run TestParse -count=1`
  - `go test ./pkg/appid -run TestProtocolNumberUnrepresentable -count=1`

No full test suite was run because this was a read-only audit report.
