# Codex Review 155 - Application/Policy Matcher Quota Campaign

Date: 2026-07-01
Repo: `/home/ps/git/codex-bpfrx`
HEAD: `5d77dbde724c`
Output file: `/tmp/codex-review-155.md`

This campaign follows `/home/ps/git/agy-do-review-audit.txt`: duplicate suppression, explicit module checklist, quota-style findings, and confidence separation. Focus for this pass is policy/application matching and AppID/NAT application consumers, not the firewall-filter semantic findings already reported in `/tmp/codex-review-154.md`.

## Duplicate Suppression

Read prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, and repo issue history snippets before writing findings. Suppressed as already covered:

- Policy simulator invalid selector/protocol/port parsing: #3108/#3116 and `/tmp/codex-review-127.md`, `/tmp/codex-review-132.md`.
- Prior policy matcher missing global/default/scheduler/source-port/excluded-address behavior: #3042, #3104, #3323, #3330, #3356, #3415.
- NAT application match dropped source-port / ICMP constraints: #3437/#3491 closed.
- DNAT/SNAT direct match port 70000 wrapping: #3446/#3450 closed.
- AppID source-port fallback ignore: #3428 closed.
- AppID catalog O(N) scan-list cold lookup: `/tmp/codex-review-001.md`.
- Broad vSRX feature gaps already in `docs/feature-gaps.md`: UTM, dynamic-applications, URL categories, source identity, force reassembly, unified policy.

## Module Checklist

Inspected modules/features:

1. `pkg/policymatch` shared policy simulator.
2. `pkg/dataplane/userspace` policy snapshot builder.
3. `pkg/dataplane/userspace` NAT application-term builders.
4. `pkg/appid` tuple fallback and catalog builder.
5. `pkg/dataplane` legacy AppNames compiler parity.
6. `userspace-dp/src/policy.rs` Rust policy/application matcher and AppCatalog.
7. `pkg/config` application-set expansion and strict application validators.
8. `pkg/config` application port canonicalization.
9. Policy simulator tests and README claims.
10. AppID/NAT application test coverage.

Negative results:

- No new finding in the normal strict commit path for policy application-set definition. `validateApplicationSetMembersStrict` and `validatePolicyMatchApplicationsStrict` reject malformed/empty sets on strict commit.
- No new finding in Rust `CompiledApplications` first-listed policy application precedence; `policy.rs` now carries order and tests exist from prior work.
- No new finding in undefined-zone transit policy matching; `pkg/policymatch` and Rust both gate unknown zones to default policy.

## Verification Commands

Throwaway tests were added and run, then removed after this report:

- `go test ./pkg/policymatch -run TestCodexAuditBadAppSetDenyFallsThroughToDefaultPermit -count=1`
- `go test ./pkg/dataplane/userspace ./pkg/policymatch -run TestCodexAuditBadAppSet -count=1`
- `go test ./pkg/appid -run TestCodexAuditTupleFallbackPortOverflowWraps -count=1`
- `go test ./pkg/appid -run TestCodexAudit -count=1`
- `go test ./pkg/dataplane/userspace -run 'TestCodexAudit(AppPortsReversedRange|BadAppSet)' -count=1`

## High Confidence Findings

### H01. Policy simulator default-permits a malformed application-set deny while userspace snapshot rejects it fail-closed

Severity: High
Confidence: High
Type: correctness/security, operator diagnostic drift

Evidence:

- `pkg/policymatch/policymatch.go:1199-1203` checks `cfg.Applications.ApplicationSets[a]`, calls `config.ExpandApplicationSet`, and `continue`s on error.
- `pkg/dataplane/userspace/capabilities.go:269-272` treats the same unresolved application-set expansion as `ok=false`.
- `pkg/dataplane/userspace/policies.go:345-361` emits the `__unsupported__` application sentinel for `ok=false`.
- `pkg/dataplane/userspace/policies.go:466-498` reports the built-rule rejection so the helper keeps previous-good or fresh-boot default-deny.

Runtime trace:

1. Config is lenient-loaded or peer-synced with a policy `then deny`, default-policy permit, and `match application bad-set`.
2. `bad-set` contains `junos-http` plus a dangling member.
3. Dataplane snapshot path marks the rule unsupported and rejects publication.
4. `pkg/policymatch.Match` skips the bad set and falls through to configured default permit.
5. Operator asks “would tcp/80 be denied?” and gets a permit verdict for traffic the dataplane does not certify that way.

Throwaway test:

- `TestCodexAuditBadAppSetDenyFallsThroughToDefaultPermit` proved `Match()` returns default permit.
- `TestCodexAuditBadAppSetSnapshotRejects` proved the snapshot path records a content rejection for the same config.

Fix direction: make `matchApp` treat application-set expansion errors the way the runtime builder does: poison the rule and return no match with an explicit unsupported-result annotation, not silent skip/default.

### H02. AppID tuple fallback wraps out-of-range single-port specs through `uint16(v)`

Severity: High
Confidence: High
Type: correctness/security observability

Evidence:

- `pkg/appid/runtime.go:270-277` parses a bare port with `strconv.Atoi` and returns `err == nil && uint16(v) == port`.
- `strconv.Atoi("70000") == 70000`; `uint16(70000) == 4464`.
- Strict commit rejects this shape, but tolerant load / stale persisted configs still pass typed `config.Application` into `ResolveSessionName`.

Runtime trace:

1. AppID is disabled, so `ResolveSessionName` uses tuple fallback.
2. A lenient config has custom application `destination-port 70000`.
3. A real TCP session to destination port 4464 is inspected.
4. `portInSpec(4464, "70000")` returns true through the narrowing cast.
5. The session is mislabeled as the malformed application.

Throwaway test: `TestCodexAuditTupleFallbackPortOverflowWraps` reproduced `70000 -> 4464`.

Fix direction: use `config.ParseCanonicalUint` or a shared application-port parser and require `1 <= v <= 65535` before comparing.

### H03. AppID catalog ignores source-port parse errors and broadens the app to any source port

Severity: High
Confidence: High
Type: correctness/security observability

Evidence:

- `pkg/appid/catalog.go:110-115` parses `app.SourcePort`; on error it ignores the error and leaves `srcLow/srcHigh` at zero.
- `userspace-dp/src/policy.rs:1584-1599` treats all-zero source bounds as unconstrained.
- `pkg/dataplane/compiler.go:580-587` has the same legacy behavior for AppNames parity, which explains why this survived: it mirrors old eBPF semantics rather than fail-closing the userspace AppID catalog.

Runtime trace:

1. AppID is enabled with a leniently-loaded custom app `protocol tcp destination-port 80 source-port 70000`.
2. `BuildCatalog` emits a TCP/80 entry with `SrcPortLow=0, SrcPortHigh=0`.
3. Rust `AppCatalog` indexes that as an unconstrained source-port exact-destination entry.
4. Any TCP/80 flow can be stamped as that malformed app.

Throwaway test: `TestCodexAuditBuildCatalogBadSourcePortBroadensEntry` verified the emitted catalog row has unconstrained source bounds.

Fix direction: treat bad source-port exactly like bad destination-port for the AppID catalog: skip the entry or return an error. If legacy AppNames parity is still required, separate ID assignment from entry validity.

### H04. NAT application port parser turns reversed ranges into exact low-port matches

Severity: High
Confidence: High
Type: correctness/security, NAT match widening

Evidence:

- `pkg/dataplane/userspace/nat.go:565-582` parses `lo-hi`; when `hi > lo` it expands the range, otherwise it returns `[]int{int(lo)}`.
- `pkg/dataplane/userspace/nat.go:443-460` feeds this into source-NAT application match terms.
- `pkg/dataplane/userspace/nat.go:794-805` feeds the same helper into destination-NAT application match terms.
- `pkg/config/compiler_applications.go:598-613` rejects `lo > hi` on strict commit, so this is a lenient-load / peer-sync backstop issue.

Runtime trace:

1. Config is lenient-loaded with an application `destination-port 200-100`.
2. A source or destination NAT rule references that application.
3. `appPortsFromSpec("200-100")` returns `[200]`, not no-match.
4. NAT applies to port 200 even though the configured range is invalid and should fail closed.

Throwaway test: `TestCodexAuditAppPortsReversedRangeBecomesLowPort` reproduced `200-100 -> [200]`.

Fix direction: make `appPortsFromSpec` reject `hi < lo`; keep `lo == hi` as exact single port.

## Medium Confidence Findings

### M01. `matchApp` and the snapshot builder still have different malformed-set semantics when a bad set is mixed with `any`

Severity: Medium
Confidence: Medium
Type: correctness/security

Evidence:

- `pkg/policymatch/policymatch.go:1193-1215` evaluates policy applications in order and returns true immediately on `any`.
- `pkg/dataplane/userspace/capabilities.go:265-272` returns false as soon as a non-empty non-any app token fails to resolve.

Runtime trace:

1. `match application [ bad-set any ]` reaches the simulator.
2. Simulator skips the bad set and then returns true for `any`.
3. Runtime expansion sees the bad set first and emits the unsupported sentinel.

This is the same root as H01 but a different operational shape: the presence of `any` after a bad token makes the simulator even more confidently wrong.

### M02. Source-NAT app-set expansion errors partially drop malformed references when another app in the list resolves

Severity: Medium
Confidence: Medium
Type: correctness/security, lenient-load behavior

Evidence:

- `pkg/dataplane/userspace/nat.go:468-482` skips an application-set entirely when `ExpandApplicationSet` returns an error.
- `pkg/dataplane/userspace/nat.go:484-487` only emits a never-match term when all configured references resolved to nothing.

Runtime trace:

1. A source-NAT rule has `match application [ good-app bad-set ]`.
2. `bad-set` has a dangling member.
3. Lenient build keeps `good-app` terms and silently drops `bad-set`.
4. The rule still translates `good-app` traffic, even though part of the operator-authored match is invalid.

Fix direction: on any configured app-set expansion error, mark the whole NAT rule/app-axis fail-closed, not partial-success, or surface a capability rejection.

### M03. Destination-NAT has the same partial-drop behavior for malformed application-sets

Severity: Medium
Confidence: Medium
Type: correctness/security, lenient-load behavior

Evidence:

- `pkg/dataplane/userspace/nat.go:817-833` expands DNAT `match application` lists and ignores application-set expansion errors.
- `pkg/dataplane/userspace/nat.go:837-853` only fail-closes when the whole configured list resolves to zero terms.

Runtime trace:

1. DNAT rule references `[ good-app bad-set ]`.
2. `bad-set` fails expansion.
3. DNAT still publishes the VIP for `good-app`.
4. A malformed policy component is silently discarded instead of making the NAT rule fail closed.

### M04. AppID catalog records `AppNames` for bad destination-port apps even when no catalog row can stamp that id

Severity: Medium
Confidence: Medium
Type: correctness/operability

Evidence:

- `pkg/appid/catalog.go:92-107` writes `cat.AppNames[appID] = name` before parsing `DestinationPort`; on parse error it `continue`s without adding a catalog entry.
- `pkg/dataplane/appid_catalog_parity_test.go:89-139` pins this behavior for compatibility with `compileApplications`.

Runtime trace:

1. A malformed app has an unparsable destination-port and is last in sorted order or has no later good app to overwrite the id.
2. `AppNames` contains a name whose id has no matching `AppCatalogEntry`.
3. Any stale/nonzero app_id from a previous helper/catalog skew resolves to the malformed app name instead of UNKNOWN.

Fix direction: preserve compiler parity for ids, but keep a separate “stamped id is valid” bit or omit `AppNames` entries for rows that cannot be emitted.

### M05. AppID tuple fallback accepts non-canonical signed-plus port specs that strict config rejects

Severity: Medium
Confidence: Medium
Type: correctness, parser drift

Evidence:

- `pkg/appid/runtime.go:270-277` uses `strconv.Atoi`; `+80` parses as 80.
- `pkg/config/compiler_applications.go:521-566` introduced canonical unsigned parsing and rejects signed forms.

Runtime trace:

1. Lenient config carries `destination-port +80`.
2. Strict commit would reject it, but tuple fallback labels destination port 80 as the app.
3. AppID-disabled session display can certify a malformed app that the dataplane policy capability gate would not represent.

Fix direction: remove `strconv.Atoi` from fallback and reuse the canonical parser.

### M06. AppID tuple fallback and AppID catalog disagree on malformed source-port handling

Severity: Medium
Confidence: Medium
Type: correctness/diagnostic consistency

Evidence:

- `pkg/appid/runtime.go:251-260` requires source-port spec to match through `portInSpec`; malformed source specs generally never match.
- `pkg/appid/catalog.go:110-115` ignores source-port parse errors and emits an unconstrained source range.

Runtime trace:

1. Same config, same custom app, same session tuple.
2. AppID disabled: tuple fallback may return UNKNOWN because bad source-port does not match.
3. AppID enabled: Rust catalog can stamp the same flow with that app because the bad source-port was dropped.

This is a mode-dependent observability split.

### M07. Reversed AppID catalog ranges are shipped as inverted bounds instead of being rejected

Severity: Medium
Confidence: Medium
Type: correctness/operability

Evidence:

- `pkg/appid/catalog.go:300-316` returns `uint16(low), uint16(high)` without `low <= high`.
- `userspace-dp/src/policy.rs:1668-1680` tests `p >= low && p <= high`, so inverted bounds never match.

Runtime trace:

1. Lenient config carries `destination-port 200-100`.
2. AppID catalog ships a row with `dst_low=200,dst_high=100`.
3. Rust silently never stamps that app.

This is fail-closed, not fail-open, but it creates an unreported AppID feature hole and diverges from the NAT parser in H04.

### M08. The application-set expansion error does not name the dangling member in policy content-rejection output

Severity: Medium
Confidence: Medium
Type: operability

Evidence:

- `pkg/dataplane/userspace/policies.go:347` captures rejected apps through `offendingApplicationTokens`.
- `pkg/dataplane/userspace/policies.go:450-452` appends the top-level app token when expansion fails.
- `pkg/dataplane/userspace/policies.go:487-498` formats only those captured tokens.

Runtime trace:

1. `bad-set` contains `missing-member`.
2. Snapshot rejection reason names `bad-set`, not `missing-member`.
3. Operator must manually inspect the set to find the actual typo.

Fix direction: return structured expansion errors with the exact dangling member and include it in `rejectedApplications`.

## Low Confidence Findings / Triage Candidates

### L01. `pkg/appid` has no regression test for tuple fallback overflow/canonical parsing

Severity: Low
Confidence: High
Type: test coverage

Evidence: existing `pkg/appid/runtime_test.go:372-424` covers source-port presence/range, but no `70000`, `+80`, or out-of-range bare port cases for `portInSpec`.

### L02. AppID catalog tests pin bad destination-port id parity but not bad source-port broadening

Severity: Low
Confidence: High
Type: test coverage

Evidence: `pkg/dataplane/appid_catalog_parity_test.go:89-139` covers malformed destination-port id drift. There is no sibling asserting malformed source-port fails closed or is intentionally broad.

### L03. NAT application parser lacks a reversed-range unit test

Severity: Low
Confidence: High
Type: test coverage

Evidence: NAT tests cover `70000` and malformed direct DNAT ports, but the duplicate application helper `pkg/dataplane/userspace/nat.go:565-582` has no `200-100` guard.

### L04. `pkg/policymatch` README overstates snapshot-builder parity for malformed application-sets

Severity: Low
Confidence: Medium
Type: documentation drift

Evidence: `pkg/policymatch/README.md` describes matching through `config.ExpandApplicationSet` and runtime parity, but `pkg/policymatch/policymatch.go:1200-1203` silently skips expansion errors while the snapshot builder emits a fail-closed sentinel.

### L05. Source-NAT/DNAT lenient-load partial-success policy is not documented as an invariant

Severity: Low
Confidence: Medium
Type: documentation/operability

Evidence: source-NAT comments at `pkg/dataplane/userspace/nat.go:416-419` explicitly say unresolvable members contribute nothing, but this is a lenient-load security posture decision and is not surfaced in operator status.

### L06. Application port parsing is duplicated across at least four packages

Severity: Low
Confidence: High
Type: modularity/refactor

Evidence:

- `pkg/config/compiler_applications.go:585-624` strict application port validation.
- `pkg/dataplane/userspace/nat.go:559-589` NAT app port expansion.
- `pkg/appid/catalog.go:296-316` AppID catalog port range parsing.
- `pkg/appid/runtime.go:263-278` tuple fallback port matching.

Observed drift: H02/H04/H03. This should be a shared `application/ports` parser, not repeated string code.

### L07. Legacy eBPF parity keeps bad AppID source-port behavior alive after eBPF retirement work

Severity: Low
Confidence: Medium
Type: refactor/retirement cleanup

Evidence: `pkg/dataplane/compiler.go:580-587` warns and broadens bad source-port, and `pkg/appid/catalog.go:110-115` mirrors that. Once legacy eBPF AppNames parity is no longer a hard invariant, this should be simplified to userspace fail-closed behavior.

### L08. `BuildCatalog` documentation promises AppID catalog build errors for malformed inputs, but bad app ports are warnings/continues

Severity: Low
Confidence: Medium
Type: documentation drift

Evidence:

- `pkg/dataplane/userspace/flow.go:135-142` says catalog build errors are propagated for malformed application-set references or id overflow.
- `pkg/appid/catalog.go:96-107` treats malformed destination-port as non-error and skips the entry.
- `pkg/appid/catalog.go:110-115` treats malformed source-port as non-error and broadens it.

### L09. AppID overlap policy is deterministic but not Junos/vSRX-specificity complete

Severity: Low
Confidence: Low
Type: feature completeness vs vSRX

Evidence: `userspace-dp/src/policy.rs:1651-1702` ranks AppID overlaps by binary port-constrained tier and then lowest app_id. It does not rank exact destination+source constraints above exact destination-only constraints except by alphabetic id. This is explicitly intentional for Go fallback parity, but it is not a rich vSRX application-identification specificity model.

### L10. No end-to-end smoke covers malformed application objects under tolerant load / peer sync

Severity: Low
Confidence: Medium
Type: validation gap

Evidence: strict commit tests are extensive, but the bugs above live in tolerant-load / peer-sync behavior where strict validation is intentionally downgraded. A targeted smoke should load a persisted malformed app-set and bad source-port app, then assert policy/NAT/AppID status reports fail-closed or explicit degradation.

### L11. Policy simulator cannot express “runtime rejected snapshot” as a first-class result

Severity: Low
Confidence: Medium
Type: API completeness

Evidence: `pkg/policymatch.Result` has match/default/action fields but no “policy content rejected by helper” state. H01 shows the simulator has to choose a normal permit/deny/default answer even when the runtime would retain previous-good state.

### L12. AppID catalog source-port badness can shadow predefined apps by sorted-name id order

Severity: Low
Confidence: Medium
Type: observability

Evidence: `pkg/appid/catalog.go:65-82` assigns ids in sorted-name order. A custom malformed `bad-src` app sorts before `junos-http`, and H03 makes it an unconstrained TCP/80 entry. Rust overlap resolution chooses the lower app_id within the same port-constrained tier (`userspace-dp/src/policy.rs:1693-1702`).

## Recommended Issues

1. Fix `pkg/policymatch` malformed application-set semantics to match userspace snapshot fail-closed behavior.
2. Harden `pkg/appid` tuple fallback port parsing against overflow and non-canonical numeric forms.
3. Make AppID catalog bad source-port parse fail closed instead of dropping the source constraint.
4. Fix NAT `appPortsFromSpec` reversed-range handling and add SNAT/DNAT regression tests.
5. Consolidate application port parsing into one shared module used by config, policy, AppID, and NAT.
6. Add tolerant-load / peer-sync malformed-application smoke coverage.

