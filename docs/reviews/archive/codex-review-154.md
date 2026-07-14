# Codex Review 154 - Firewall Filter / Policy Semantic Audit

Date: 2026-07-01
Repo: `/home/ps/git/codex-bpfrx`
HEAD: `5d77dbde724c`
Focus: vSRX-core firewall correctness, especially stateless firewall filters, lo0 host-bound enforcement, and the Rust userspace filter matcher.

## Campaign Setup

- Ran `git pull --rebase`: already up to date.
- Read `/home/ps/git/agy-do-review-audit.txt`.
- Duplicate suppression:
  - Read prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` by targeted `rg`.
  - Read relevant closed issue/PR history from `docs/issues/issue-history.md` and `docs/issues/pr-history.md`.
  - Suppressed known/closed items: host-inbound zone identity collisions from review 153, from-zone `junos-host` host-originated policy gap, default-policy logging, filter address/flex/DSCP/tcp-flags parse gates, application #3373 port-on-non-port, application #3348 ICMP semantic gates, policy ordering/global wildcard gates, flowless fragment enforcement, filter counter nil slots, lo0 fall-through #3427, and no-catchall warnings.

## Module Checklist

1. `pkg/config/compiler_firewall.go` - firewall-filter parser/lowering.
2. `pkg/config/compiler_validate_strict.go` - strict semantic validation gates.
3. `pkg/config/compiler_validate_warn.go` - warn-only operator visibility.
4. `pkg/dataplane/userspace/filters.go` - Go snapshot builder for userspace filters.
5. `userspace-dp/src/filter/compiler.rs` - Rust filter snapshot compiler.
6. `userspace-dp/src/filter/engine/matching.rs` - Rust hot-path term matcher.
7. `userspace-dp/src/filter/engine/eval.rs` - input/output/lo0 evaluation.
8. `userspace-dp/src/policy.rs` - zone policy precedence and default-policy path.
9. `pkg/daemon/daemon_nft.go` - kernel lo0 nftables mirror.
10. `pkg/config/compiler_lo0_mirror_modifiers_3445_test.go` - lo0 warning coverage.
11. `userspace-dp/src/filter/tests.rs` - Rust filter semantic coverage.
12. `docs/config-schema.md`, `docs/feature-gaps.md`, `docs/issues/*.md` - issue history and vSRX parity notes.

Negative results:

- Zone-policy precedence itself looked well covered in this pass: exact zone-pair, single-wildcard, both-any, global, and implicit default-policy are explicitly ordered in `userspace-dp/src/policy.rs`, and prior reports already cover host-inbound identity hazards.
- Reject-reply truthfulness looked covered: `reject_reply.rs` emits synthetic replies and event logging uses enqueue outcome before RT_FLOW emission. I did not find a non-duplicate issue there this round.
- The known application semantic gates for ports on non-port protocols and ICMP type/code misuse exist; the new issue below is that firewall filters did not receive the same cross-field gates.

## Commands / Runtime Probes

Temporary tests were added, run, and removed. The worktree was clean afterward.

```text
go test ./pkg/config -run TestCodexAuditFilterPortOnNonPortProtocolCommits -count=1
ok  	github.com/psaab/xpf/pkg/config	0.004s

go test ./pkg/config -run TestCodexAuditFilterTCPFlagsOnUDPCommits -count=1
ok  	github.com/psaab/xpf/pkg/config	0.004s

go test ./pkg/config -run TestCodexAuditFilterICMPTypeOnTCPCommits -count=1
ok  	github.com/psaab/xpf/pkg/config	0.006s

go test ./pkg/config -run TestCodexAuditFilterICMPCodeWithoutTypeCommits -count=1
ok  	github.com/psaab/xpf/pkg/config	0.005s

go test ./pkg/config -run TestCodexAuditLo0RoutingInstanceNoKernelMirrorWarning -count=1
ok  	github.com/psaab/xpf/pkg/config	0.004s
```

## High Confidence Findings

### H01 - Firewall filters still accept ports on non-port protocols; deny terms never match

- Severity: High
- Confidence: High
- Type: correctness/security
- Evidence:
  - `pkg/config/compiler_firewall.go:268-286` stores `from protocol` and `from destination-port` independently:
    - `term.Protocols = append(term.Protocols, firewallMatchValues(child)...)`
    - `term.DestinationPorts = append(term.DestinationPorts, resolveFilterPortTokens(...))`
  - `pkg/config/compiler_validate_strict.go:3613-3645` has the #3373 gate for applications only: a port on non-port protocol becomes a never-match and is rejected.
  - `pkg/dataplane/userspace/filters.go:111-119` emits both protocol and port constraints to the filter snapshot without checking compatibility.
  - `userspace-dp/src/filter/engine/matching.rs:188-223` checks protocol first, then `port_match` regardless of protocol. For GRE/ESP/AH/OSPF/VRRP/SCTP the parsed packet ports are zero/absent, so a `destination-port 80` term never matches.
- Runtime trace:
  - Temporary test compiled:
    - `set firewall family inet filter f term deny-gre-web from protocol gre`
    - `set firewall family inet filter f term deny-gre-web from destination-port 80`
    - `set firewall family inet filter f term deny-gre-web then discard`
  - Strict `CompileConfig` accepted it.
  - Runtime GRE packet has protocol 47 and no extracted L4 port; `port_match(..., dst_port=0)` rejects the term. A later permit/default can allow traffic the operator attempted to discard.
- Non-duplicate note:
  - #3373 fixed this for `applications`, not for `firewall family inet/inet6 filter` terms.
- Fix direction:
  - Add a firewall-filter semantic gate mirroring `protocolIsPortBearing` for `SourcePorts`, `DestinationPorts`, `SourcePortsExcept`, and `DestPortsExcept`.
  - If no protocol is specified, keep current Junos-like behavior. If a multi-protocol list mixes port-bearing and non-port-bearing protocols, reject or require split terms.

### H02 - Firewall filters accept `tcp-flags` with a non-TCP protocol; deny terms become never-match

- Severity: High
- Confidence: High
- Type: correctness/security
- Evidence:
  - `pkg/config/compiler_firewall.go:206-218` validates only that the `tcp-flags` expression is parseable; it does not require an absent protocol or TCP-only protocol.
  - `userspace-dp/src/filter/engine/matching.rs:33-39` explicitly returns false when a term has TCP flags but the packet protocol is not TCP.
- Runtime trace:
  - Temporary test compiled:
    - `set firewall family inet filter f term deny-udp-syn from protocol udp`
    - `set firewall family inet filter f term deny-udp-syn from tcp-flags syn`
    - `set firewall family inet filter f term deny-udp-syn then discard`
  - Strict `CompileConfig` accepted it.
  - Runtime UDP packets never match because `protocol != PROTO_TCP`; the discard is dead.
- Fix direction:
  - Add a firewall-filter cross-field gate: if `tcp-flags` is present and `protocol`/`next-header` is present, every protocol token must resolve to TCP. Mixed `[ tcp udp ]` should be rejected or split.

### H03 - Firewall filters accept ICMP type/code with non-ICMP protocols; deny terms become never-match

- Severity: High
- Confidence: High
- Type: correctness/security
- Evidence:
  - `pkg/config/compiler_firewall.go:315-335` resolves ICMP type/code tokens independently of `from protocol`.
  - `userspace-dp/src/filter/engine/matching.rs:59-77` gates ICMP type/code on `protocol == PROTO_ICMP || protocol == PROTO_ICMPV6`; non-ICMP packets never match those terms.
  - `pkg/config/compiler_validate_strict.go:3694-3711` has this exact semantic gate for applications, but no equivalent firewall-filter pass was found.
- Runtime trace:
  - Temporary test compiled:
    - `set firewall family inet filter f term deny-tcp-echo from protocol tcp`
    - `set firewall family inet filter f term deny-tcp-echo from icmp-type echo-request`
    - `set firewall family inet filter f term deny-tcp-echo then discard`
  - Strict `CompileConfig` accepted it.
  - Runtime TCP packets never match because the term requires ICMP type membership.
- Fix direction:
  - Add a firewall-filter semantic gate: if `icmp-type` or `icmp-code` is present and protocol/next-header is specified, every protocol token must resolve to ICMP/ICMPv6 as appropriate for the filter family.

## Medium Confidence Findings

### M01 - Multi-protocol firewall terms can silently partially enforce protocol-specific match fields

- Severity: Medium
- Confidence: Medium
- Type: correctness/completeness
- Evidence:
  - The same code paths as H01-H03 accept multi-value `from protocol` lists and independent match fields.
  - `pkg/config/compiler_firewall.go:268-275` accumulates every protocol token.
  - `userspace-dp/src/filter/engine/matching.rs:33-39` and `:59-77` make TCP/ICMP-only fields reject non-matching protocols at runtime.
- Runtime trace:
  - A term like `from protocol [ tcp udp ]; from tcp-flags syn; then discard` discards TCP SYN but never matches UDP. A term like `from protocol [ icmp tcp ]; from icmp-type echo-request; then discard` discards echo-request but never matches TCP.
- Why this matters:
  - Operators frequently use bracket lists to keep a security term compact. This behavior makes a single configured deny look broader than the actual runtime enforcement.
- Fix direction:
  - Reject mixed protocol lists when any protocol-specific field is present, or auto-split only if semantics are provably faithful and visible in show/trace output.

### M02 - `next-header` inherits the same protocol-specific-field hazards in inet6 filters

- Severity: Medium
- Confidence: High
- Type: correctness/completeness
- Evidence:
  - `pkg/config/compiler_firewall.go:268-275` treats `next-header` as an alias for `protocol`.
  - H01-H03 gates are missing at the shared term level.
- Runtime trace:
  - `family inet6 filter f term t from next-header gre destination-port 80 then discard` has the same never-match port constraint as IPv4 GRE.
- Fix direction:
  - Implement the semantic compatibility check after `compileFilterFrom` has populated `term.Protocols`, so it naturally covers both `protocol` and `next-header`.

### M03 - Firewall filters allow ICMP code-only terms while applications explicitly reject the same ambiguity

- Severity: Medium
- Confidence: Medium
- Type: correctness / Junos parity
- Evidence:
  - `pkg/config/compiler_validate_strict.go:3713-3723` rejects application `icmp-code` without `icmp-type` as ambiguous.
  - Firewall filter compile path has no analogous gate; temporary test accepted:
    - `from protocol icmp`
    - `from icmp-code 0`
    - `then discard`
  - `userspace-dp/src/filter/engine/matching.rs:71-77` can match code alone across ICMP types.
- Runtime trace:
  - Code `0` is common across multiple ICMP types. A code-only term can match a broader or different set than an operator expects if they imported a vSRX config assuming type+code pairing.
- Fix direction:
  - Decide whether Junos firewall filters allow code-only terms. If not, mirror the application gate. If yes, document this as an intentional filter/app semantic difference and add tests.

### M04 - lo0 `then routing-instance` warns for neither side effect loss nor kernel-primary route-selection bypass

- Severity: Medium
- Confidence: High
- Type: feature completeness / operator visibility
- Evidence:
  - `pkg/daemon/daemon_nft.go:1103-1113` says routing-instance terms terminate as accept in the kernel lo0 mirror because nft cannot perform route selection.
  - `pkg/config/compiler_validate_warn.go:1027-1035` warns only for `policer`, `dscp`, and `forwarding-class`; no `routing-instance` warning is emitted.
  - Temporary test confirmed `ValidateConfig` produced no `kernel lo0 input mirror` warning for an lo0 input filter with `then routing-instance blue`.
- Runtime trace:
  - Host-bound traffic to firewall interface IPs/VRRP VIPs takes the kernel lo0 path first. A PBR-style lo0 term is accepted locally rather than route-selected. That may be the safest verdict behavior, but the operator is not told the routing side effect is not honored on the primary path.
- Fix direction:
  - Add `routing-instance` to the lo0 mirror warning surface with wording that the verdict is accepted but route selection cannot be performed by the kernel hook.

### M05 - Closed issue/PR history for lo0 routing-instance mirror is now stale relative to code

- Severity: Medium
- Confidence: High
- Type: documentation drift
- Evidence:
  - `docs/issues/pr-history.md` for PR #3465 says routing-instance terms are skipped and warn once.
  - Current `pkg/daemon/daemon_nft.go:1103-1113` says they intentionally emit terminating accept.
  - Current `pkg/config/compiler_validate_warn.go:1027-1035` does not warn for routing-instance.
- Runtime trace:
  - This doc drift can mislead reviewers and operators auditing why a lo0 PBR term does or does not affect host-bound traffic.
- Fix direction:
  - Update issue/pr history or operator docs to the current contract, and add a canary that pins the warning/accept behavior.

### M06 - lo0 nft `log` mirrors `then log/syslog` with no visible rate limiter

- Severity: Medium
- Confidence: Medium
- Type: availability/performance
- Evidence:
  - `pkg/daemon/daemon_nft.go:1128-1131` emits bare nft `log prefix "..."`
  - No `limit rate` or equivalent throttle appears in the lo0 rule rendering.
- Runtime trace:
  - A permitted high-rate host-bound flow matching a logged lo0 term can push every packet into kernel logging/journald. On a firewall/router, control-plane log amplification can become an availability issue.
- Fix direction:
  - Add per-term rate limiting for kernel lo0 log rules, or require explicit `syslog`/`log` risk documentation and expose a global cap.

### M07 - lo0 nft counters are declared locally but not integrated into xpf counter status

- Severity: Medium
- Confidence: Medium
- Type: observability/completeness
- Evidence:
  - `pkg/daemon/daemon_nft.go:1121-1124` declares named nft counters for lo0 terms.
  - The comment at `pkg/daemon/daemon_nft.go:147-149` notes deletes reset counters and says this does not affect xpf metrics because these counters are not scraped.
  - Userspace filter counters are exposed through `FilterTermCounters`; kernel lo0 counters are not merged into that status path.
- Runtime trace:
  - A host-bound drop enforced by the kernel lo0 mirror may be visible in `nft list table`, but not in the same xpf CLI/API surfaces as userspace filter counters.
- Fix direction:
  - Add a daemon-side nft counter reader and merge lo0 input filter counters into `show firewall`/REST/gRPC, with generation reset semantics documented.

### M08 - lo0 mirror accepts unexpected explicit actions while Rust filter compiler fails them closed

- Severity: Medium
- Confidence: Medium
- Type: mixed-version consistency
- Evidence:
  - `pkg/daemon/daemon_nft.go:1171-1179` maps any non-`discard`, non-`reject` terminating action to `accept`.
  - `userspace-dp/src/filter/compiler.rs:593-618` maps an unknown non-empty action string to `FilterAction::Discard`.
  - `pkg/config/compiler_validate_strict.go:4079-4135` rejects normal committed unknown actions, so this is a mixed-version/hand-built-config hazard, not a fresh commit path.
- Runtime trace:
  - A tolerant load path or future peer snapshot with a new action string could fail closed in userspace while the lo0 kernel mirror accepts host-bound traffic.
- Fix direction:
  - Make the lo0 renderer fail closed for unknown non-empty actions or refuse to install the mirror with a loud warning, matching Rust.

### M09 - `nftLo0LogPrefix` strips quotes/backslashes but leaves other control bytes

- Severity: Medium
- Confidence: Medium
- Type: robustness
- Evidence:
  - `pkg/daemon/daemon_nft.go:1201-1208` removes only `"` and `\`, then byte-truncates to 64.
  - If term names can enter through an import/API path with control bytes, logs can be split/spoofed or UTF-8 can be truncated mid-rune.
- Runtime trace:
  - The parser normally constrains names, so this is not a standard CLI path bug. It is still a defensive boundary for imported configs and future API writes.
- Fix direction:
  - Sanitize to printable ASCII for nft log prefixes and truncate by rune or by an explicit escaped byte budget.

### M10 - Firewall-filter semantic validation is split by token class, so cross-field contradictions are easy to miss

- Severity: Medium
- Confidence: High
- Type: modularity/correctness
- Evidence:
  - Individual gates exist for protocols, actions, match values, flex, port-except, address-except, address literals, and application-specific semantics.
  - H01-H03 show the missing class: relationships between independently valid fields.
- Runtime trace:
  - The application validator already learned these invariants under #3373/#3348. Firewall filters missed them because there is no single pass that can reason over the whole term.
- Fix direction:
  - Add `validateFilterSemanticCompatibilityStrict` that owns protocol/port/tcp-flags/icmp/family relationships and is tested with a cross-product table.

## Low Confidence / Design / Test Findings

### L01 - Add permanent regression tests for firewall-filter port-on-non-port protocols

- Severity: Low
- Confidence: High
- Type: test gap
- Suggested tests:
  - `protocol gre + destination-port`
  - `protocol sctp + source-port`
  - numeric `47 + destination-port`
  - `next-header gre + destination-port` for inet6.

### L02 - Add permanent regression tests for firewall-filter TCP-only fields

- Severity: Low
- Confidence: High
- Type: test gap
- Suggested tests:
  - `protocol udp + tcp-flags syn` rejects.
  - `[ tcp udp ] + tcp-flags syn` rejects or requires split.
  - bare `tcp-flags syn` still commits and implies TCP at runtime.

### L03 - Add permanent regression tests for firewall-filter ICMP-only fields

- Severity: Low
- Confidence: High
- Type: test gap
- Suggested tests:
  - `protocol tcp + icmp-type echo-request` rejects.
  - `[ icmp tcp ] + icmp-type echo-request` rejects or requires split.
  - `icmp-code` without `icmp-type` is either rejected or explicitly documented with tests.

### L04 - Share protocol semantic compatibility tables between applications and firewall filters

- Severity: Low
- Confidence: Medium
- Type: modularity/refactor
- Rationale:
  - `protocolIsPortBearing` and `protocolIsICMPFamily` are already the right conceptual SSOT for applications. Firewall filters should not re-learn the same invariants through copy/paste.

### L05 - Build a property-style filter semantic matrix

- Severity: Low
- Confidence: Medium
- Type: test coverage
- Rationale:
  - Generate protocol families `{tcp, udp, icmp, icmpv6, gre, esp, ah, sctp, numeric}` crossed with match fields `{ports, tcp-flags, icmp-type, icmp-code, flex, fragment}` and assert compile/runtime behavior is intentional.

### L06 - Add Rust runtime tests for contradictory firewall-filter terms

- Severity: Low
- Confidence: High
- Type: test coverage
- Rationale:
  - The Go tests prove compile acceptance. Rust tests should prove the resulting term never matches, to pin the security impact and prevent future "fixes" from silently changing runtime behavior without a commit gate.

### L07 - Split firewall filter validation into a package-style module rather than more `compiler_*.go` flat files

- Severity: Low
- Confidence: Medium
- Type: modularity/refactor
- Suggested shape:
  - `pkg/config/firewallfilter/parse.go`
  - `pkg/config/firewallfilter/semantic.go`
  - `pkg/config/firewallfilter/warnings.go`
  - `pkg/config/firewallfilter/render_test.go`
- Rationale:
  - The current flat files hide cross-field invariants across compiler, strict validator, warning validator, and dataplane lowering.

### L08 - Split Rust filter compiler/evaluator modules around parse, integrity, matcher, counters, and lo0

- Severity: Low
- Confidence: Medium
- Type: modularity/refactor
- Suggested shape:
  - `userspace-dp/src/filter/compiler/{snapshot.rs, integrity.rs, ports.rs, icmp.rs}`
  - `userspace-dp/src/filter/engine/{input.rs, output.rs, lo0.rs, counters.rs}`
- Rationale:
  - The code is already partially split, but semantic ownership still spans `compiler.rs`, `matching.rs`, and large tests. Cross-field bugs like H01-H03 become easier to pin when each semantic family has a local table.

### L09 - Use nft sets/maps for large lo0 address and port lists instead of fully linear rule rendering

- Severity: Low
- Confidence: Medium
- Type: performance/latency
- Rationale:
  - `buildLo0FilterPayload` renders predicate-heavy rules linearly. Large vSRX-style protect filters and prefix-lists can make every host-bound packet walk many comparisons in the kernel input hook.

### L10 - Expose a "show effective firewall-filter" / explain surface

- Severity: Low
- Confidence: Medium
- Type: feature completeness vs vSRX
- Rationale:
  - Operators need to see when a filter term is unsupported, kernel-only, userspace-only, warning-only, or partially mirrored. This would have made the lo0 routing-instance contract obvious.

### L11 - Add a vSRX-parity label for firewall-filter semantic compatibility issues

- Severity: Low
- Confidence: Medium
- Type: project hygiene
- Rationale:
  - H01-H03 are not only bugs; they are parity gaps where the config language can express a term the dataplane cannot faithfully enforce. They should be labeled separately from generic refactor bugs.

### L12 - Add CI that proves application and firewall-filter protocol compatibility gates stay aligned

- Severity: Low
- Confidence: Medium
- Type: test coverage
- Rationale:
  - The application path already rejects port-on-non-port and ICMP-on-non-ICMP. A shared cross-package canary would have caught the firewall-filter omission.

### L13 - Document SCTP firewall semantics explicitly

- Severity: Low
- Confidence: Medium
- Type: feature completeness vs vSRX
- Rationale:
  - `protocolIsPortBearing` documents SCTP as having wire ports but not extracted by this dataplane. Firewall filters currently allow SCTP + ports (H01). Even after a commit gate, the docs should state whether SCTP is protocol-only until CRC32c-aware parsing/rewrite exists.

### L14 - Add lo0 nft log-rate validation to smoke/perf tests

- Severity: Low
- Confidence: Medium
- Type: test coverage/performance
- Rationale:
  - A control-plane firewall feature should not be able to saturate journald under expected traffic. A test can install a logged lo0 term and assert rate limiting or documented behavior.

### L15 - Merge kernel lo0 counters and userspace filter counters under one operator contract

- Severity: Low
- Confidence: Medium
- Type: observability/refactor
- Rationale:
  - Today host-bound kernel counters and userspace filter counters live in separate planes. A router/firewall operator expects a single view of term hits regardless of which enforcement path handled the packet.

### L16 - Add source-level canaries around `then routing-instance` lo0 rendering and warnings

- Severity: Low
- Confidence: High
- Type: test coverage
- Rationale:
  - PR history and current code already diverged once. Pinning the intended accept-vs-skip-vs-warn contract would prevent another silent drift.

### L17 - Add an import-fuzzer for firewall term names used in nft log prefixes

- Severity: Low
- Confidence: Low
- Type: robustness/test
- Rationale:
  - Standard CLI names may already be sane, but imported configs/API paths deserve a fuzzer that tries quotes, backslashes, newlines, non-ASCII, and overlong names through the nft renderer.

### L18 - Generate filter term semantic docs from the validator tables

- Severity: Low
- Confidence: Low
- Type: docs/modularity
- Rationale:
  - Once semantic compatibility is centralized, docs should be generated or checked from it so "ports valid only on TCP/UDP" and "icmp-code requires icmp-type" cannot drift between applications and firewall filters.

### L19 - Add a stateless-filter conformance suite against imported vSRX configs

- Severity: Low
- Confidence: Medium
- Type: feature completeness vs vSRX
- Rationale:
  - The current tests pin individual bugs. A conformance suite with real Junos/vSRX edge cases would catch invalid/ambiguous combinations before they reach the dataplane.

### L20 - Add per-module ownership docs for firewall semantics

- Severity: Low
- Confidence: Low
- Type: modularity/refactor
- Rationale:
  - Security behavior is split across config, daemon nft mirror, Go snapshot building, and Rust runtime. A short ownership doc stating which layer owns syntax, semantic compatibility, wire integrity, runtime fallback, and operator warnings would reduce future split-brain fixes.
