# codex Review Audit 131 - Core Firewall / vSRX Policy Correctness Campaign

## 1. Base Commit Reviewed

- Repository: `/home/ps/git/codex-bpfrx`
- Base commit: `f427b03e3`
- Pull status: `git pull --rebase` completed before inspection; branch fast-forwarded to `f427b03e3`.
- Output path: `/tmp/codex-review-131.md`
- Numbering choice: `/tmp/agy-review-131.md` already exists and `/tmp/codex-review-131.md` did not, so this report reuses `131` to keep concurrent agent numbering aligned.
- Campaign focus: core vSRX/SRX firewall behavior, especially zone policies, `junos-host`, host-inbound admission, default policy logging, policy simulation, and parser/compiler surfaces that can make "allowed" traffic drop or "denied" traffic admit.

## 2. Duplicate Suppression Summary

Prior review files scanned for duplicates:

- `/tmp/codex-review-001.md`, `002`, `121`, `122`, `123`, `125`, `127`, `128`
- `/tmp/agy-review-001.md`, `002`, `003`, `004`, `005`, `121`, `122`, `124`, `125`, `126`, `127`, `128`, `129`, `130`, `131`
- Repo documentation used as issue memory: `docs/feature-gaps.md`, `docs/host-inbound-service-matrix.md`, `pkg/cli/README.md`, `pkg/api/README.md`, and `README.md`.

Suppressed as already covered:

- Host-inbound no-stanza display/API wording and default-deny visibility gaps from earlier Codex reviews.
- Per-interface host-inbound physical/logical ifindex mismatch, which AGY-131 explicitly suppresses too.
- Ident-reset AF_XDP parity, ESP/AH global-accept, `protocols all`/IS-IS, router-discovery v6-global accept, and other host-inbound token-matrix issues already documented or reported.
- REST/gRPC policy ID zero and policy inventory drift already addressed in prior reports and current code comments.
- AGY-131 issues: conntrack GC race, static NAT shadowing, signed port split, dynamic-address feed lenient-load bypass.
- General vSRX feature gaps already listed in `docs/feature-gaps.md`: Unified Policies, dynamic-application/AppID, URL categories, source identity, UTM/IDP/SSL-proxy/application-services, SecIntel profile integration, and force IP reassembly.

## 3. Module Checklist and Inspection Log

Inspected modules/features:

1. `pkg/config/compiler_security.go` - security zones, host-inbound compiler, policy `then` compiler, default-policy/default-policy-log, pre-id-default-policy.
2. `pkg/config/schema_security.go` - schema for host-inbound, policy `then`, default-policy-log, and pre-id-default-policy.
3. `pkg/config/compiler_validate_strict.go` - strict validators for policy log action and host-inbound token allowlists.
4. `pkg/dataplane/userspace/zones.go` - zone snapshot and interface host-inbound map lowering.
5. `userspace-dp/src/afxdp/forwarding_build/zones.rs` - Rust zone table population from Go snapshots.
6. `userspace-dp/src/afxdp/forwarding/host_inbound.rs` - Rust host-inbound admission and tests.
7. `userspace-dp/src/policy.rs` - policy evaluation, wildcard/global tiers, `junos-host`, app matching, policy result metadata.
8. `userspace-dp/src/afxdp/poll_descriptor/mod.rs` - local-delivery host-inbound, lo0, `junos-host`, session install, conntrack publication.
9. `pkg/dataplane/userspace/policies.go` - policy snapshot construction, runtime policy ID allocation, app expansion.
10. `pkg/policymatch/policymatch.go` - `show security match-policies` simulator logic for transit and `junos-host`.
11. `pkg/dataplane/userspace/capabilities.go` - userspace application representability and app term expansion.
12. Tests under `pkg/config`, `pkg/dataplane/userspace`, `pkg/policymatch`, and `userspace-dp/src/*_tests.rs` relevant to the inspected paths.

Negative results:

- Structured REST/gRPC policy inventories now display runtime/span-accumulated policy IDs; raw IDs remain only as counter handles. No new issue there.
- Flat `then permit log ...`, `then permit count`, `then reject log ...`, and `then reject count` are rejected by the strict gates. No issue there.
- Session-hit host-inbound LocalDelivery path does emit host-inbound deny counters and tuple events; no stale finding there.
- `policy.rs` transit precedence for exact, single-wildcard, both-any, and global policies is well documented and matched by the simulator for transit. No new ordering bug found in that tier.

Probe commands run:

- `go run /tmp/check_hostinbound_parse.go`
- `go run /tmp/check_hostinbound_typo.go`
- `go run /tmp/check_policy_then_shapes.go`
- `go run /tmp/check_default_log_brackets.go`

## 4. High Confidence Findings

### C131-H01 - Host-inbound flat/bracket list syntax drops every value after the first

- Severity: High
- Confidence: High, directly reproduced.
- Labels: `bug`, `security`, `firewall`, `host-inbound`, `vsrx-parity`, `tests`
- Evidence:
  - `pkg/config/schema_security.go:109-120` models `system-services` / `protocols` as child containers, not `multi` value leaves.
  - `pkg/config/ast_edit.go:237-280` only collapses trailing bracket-list values when `childSchema.children == nil && childSchema.multi`.
  - `pkg/config/compiler_security.go:430-455` parses only `hit.Children`; it never reads `hit.Keys[1:]`.
- Repro output:
  - `system-services [ ssh ping ]` compiled to `SystemServices: []string{"ssh"}`.
  - `protocols [ ospf bgp ]` compiled to `Protocols: []string{"ospf"}`.
  - The same loss happened at zone level and interface override level.
- Runtime trace:
  1. Operator configures `set security zones security-zone trust host-inbound-traffic system-services [ ssh ping ]`.
  2. Flat-set parser strips brackets; `SetPath` does not mark the remaining tokens as values for the same leaf.
  3. `parseHostInboundNode` sees only the first child.
  4. `buildZoneSnapshots` sends only `ssh` to Rust.
  5. ICMP echo that vSRX syntax intended to allow is denied.
- Why it matters: This is a core management-plane access bug: intended permits are silently lost.
- Fix direction: Make host-inbound `system-services` and `protocols` real multi-value leaves or teach `parseHostInboundNode` to read `hit.Keys[1:]` exactly like policy match address/application parsing.

### C131-H02 - Host-inbound invalid bracket-list tail bypasses strict validation

- Severity: High
- Confidence: High, directly reproduced.
- Labels: `bug`, `validation`, `security`, `host-inbound`, `vsrx-parity`
- Evidence:
  - `pkg/config/compiler_validate_strict.go:6111-6128` validates only the compiled `hib.SystemServices` / `hib.Protocols` slices.
  - The parser/compiler path above drops tail tokens before validation.
- Repro output:
  - `system-services sssh` correctly errors.
  - `system-services [ ssh sssh ]` compiles `OK`.
  - `protocols [ ospf notaproto ]` compiles `OK`.
- Runtime trace:
  1. Operator mistypes the second token in a list.
  2. Parser drops that token.
  3. Strict validation never sees it.
  4. Commit succeeds with a narrower policy than authored.
- Why it matters: A firewall config should fail loudly on typos. Silent narrowing can strand management/routing protocols and masks operator error.
- Fix direction: Preserve and validate every list token; add strict parser tests for valid and invalid bracket lists at zone and interface scopes.

### C131-H03 - Named policy `then log [ session-init session-close ]` drops `session-close`

- Severity: High
- Confidence: High, directly reproduced.
- Labels: `bug`, `firewall`, `policy-logging`, `vsrx-parity`, `tests`
- Evidence:
  - `pkg/config/schema_security.go:74-90` gives `then log` children but does not model `session-init/session-close` as a multi-value list.
  - `pkg/config/compiler_security.go:710-719` creates `PolicyLog` and reads only `t.Children`.
  - Existing tests cover separate set lines, not one-line/bracket list syntax.
- Repro output:
  - Separate lines: `log=&config.PolicyLog{SessionInit:true, SessionClose:true}`.
  - `then log [ session-init session-close ]`: `log=&config.PolicyLog{SessionInit:true, SessionClose:false}`.
- Runtime trace:
  1. Operator configures a permit/deny/reject policy with both session-init and session-close logging on one set line.
  2. Compiler keeps only `session-init`.
  3. `buildOneRuleSnapshot` copies only `LogSessionInit`.
  4. Dataplane emits create logs but not close logs.
- Why it matters: Audit trails miss session-close records despite valid-looking security policy syntax.
- Fix direction: Add a shared log-option parser that reads both child nodes and `Keys[1:]`; cover zone-pair and global policies.

### C131-H04 - Named policy invalid `then log` tail commits if the first token is valid

- Severity: High
- Confidence: High, directly reproduced.
- Labels: `bug`, `validation`, `policy-logging`, `vsrx-parity`
- Evidence:
  - `pkg/config/compiler_validate_strict.go:3280-3310` only rejects a `PolicyLog` with both booleans false; it does not validate raw option names.
  - Because `bad-tail` is dropped by the parser/compiler, the validator sees `SessionInit=true` and accepts.
- Repro output:
  - `then log [ session-init not-a-real-option ]` compiled with `SessionInit:true`, `SessionClose:false`, no error.
- Runtime trace:
  1. Operator writes one valid log option followed by a typo.
  2. The typo vanishes before strict validation.
  3. Commit succeeds with no diagnostic.
- Why it matters: This breaks Junos-style fail-fast config validation on a security audit control.
- Fix direction: Validate raw `then log` child/key tokens against `{session-init, session-close}` before compiling, or preserve all keys into the compiler.

### C131-H05 - `default-policy-log [ session-init session-close ]` drops `session-close`

- Severity: High
- Confidence: High, directly reproduced.
- Labels: `bug`, `default-policy`, `policy-logging`, `vsrx-parity`
- Evidence:
  - `pkg/config/schema_security.go:155-165` models `default-policy-log` as a child container.
  - `pkg/config/compiler_security.go:529-543` checks only `FindChild("session-init")` and `FindChild("session-close")`.
  - `userspace-dp/src/policy.rs:2838-2849` stamps default-policy log flags onto default verdict results, so this is not inert under `permit-all`.
- Repro output:
  - Separate lines: `default-init=true default-close=true`.
  - Bracket list: `default-init=true default-close=false`.
- Runtime trace:
  1. Operator configures implicit default-policy logging for both create and close.
  2. Compiler keeps only create logging.
  3. A default-permit session gets create log metadata but no close log metadata.
- Why it matters: The default policy is the most security-relevant fallback. Losing close logs on that path hides session duration/byte-close accounting.
- Fix direction: Parse default-policy-log options through the same shared log-option list helper as policy `then log`.

### C131-H06 - `default-policy-log` accepts unknown tokens as silent no-ops

- Severity: High
- Confidence: High, directly reproduced.
- Labels: `bug`, `validation`, `default-policy`, `policy-logging`
- Evidence:
  - `pkg/config/compiler_security.go:537-543` ignores anything except `session-init` / `session-close`.
  - No strict validator analogous to `validatePolicyLogActionStrict` exists for `default-policy-log`.
- Repro output:
  - `set security policies default-policy-log bad-tail` compiled with `default-init=false default-close=false warnings=[]`.
  - `default-policy-log [ session-init bad-tail ]` compiled with `default-init=true default-close=false warnings=[]`.
- Runtime trace:
  1. Operator misspells a default-policy log option.
  2. Compile path ignores it.
  3. No strict validation error or warning is emitted.
- Why it matters: It makes a security logging knob look configured while it is partially or completely inert.
- Fix direction: Add strict validation for `default-policy-log` raw children/keys and fail on unknown tokens.

### C131-H07 - `to-zone junos-host then permit log ...` is ignored on local-delivery sessions

- Severity: High
- Confidence: High from code path inspection.
- Labels: `bug`, `junos-host`, `policy-logging`, `vsrx-parity`, `userspace-dataplane`
- Evidence:
  - `userspace-dp/src/policy.rs:2937-3048` returns a full `PolicyEvaluationResult` for `junos-host`, including log flags from `try_match_rule`.
  - `userspace-dp/src/policy.rs:3215-3229` fills `log_session_init`, `log_session_close`, and `policy_id`.
  - `userspace-dp/src/afxdp/poll_descriptor/mod.rs:96-119` discards the result on `PolicyAction::Permit` by returning `None`.
  - `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1954-1979` installs local-delivery sessions with both log flags forced false.
- Runtime trace:
  1. Policy: `from-zone trust to-zone junos-host policy allow-ssh then permit` plus `then log session-init session-close`.
  2. Host-bound SSH passes host-inbound.
  3. `evaluate_junos_host_policy_l3_aware` matches the permit and carries log flags.
  4. Wrapper returns `None`; caller treats permit the same as no matching host policy.
  5. Local session metadata disables policy logging.
- Why it matters: Management-plane permit policies cannot produce the RT_FLOW audit records operators expect from vSRX policy logging.
- Fix direction: Return the full `PolicyEvaluationResult` from the junos-host gate. Drop on deny/reject, but stamp permit metadata on the local session.

### C131-H08 - `junos-host` permit sessions publish policy identity as zero

- Severity: High
- Confidence: High from code path inspection.
- Labels: `bug`, `junos-host`, `policy-id`, `observability`, `vsrx-parity`
- Evidence:
  - Same result-discard path as C131-H07.
  - `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1970-1978` hardcodes `policy_id: 0`, `policy_counter_idx: 0`, and `policy_counter: None`.
  - `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2021-2029` publishes conntrack with that metadata.
- Runtime trace:
  1. A `junos-host` permit policy admits host-local traffic.
  2. The cached local session and published conntrack row carry policy ID 0.
  3. Show/API/session consumers cannot distinguish "matched first policy" from "host-local no policy identity."
- Why it matters: This breaks event/session-to-policy join workflows on host-bound management traffic.
- Fix direction: Stamp `result.policy_id` and counter handle on permit local sessions, or define an explicit sentinel if the product intentionally declines host-policy attribution.

### C131-H09 - Tolerant nil zone snapshots can make a configured zone host-inbound admit-all

- Severity: High
- Confidence: High for the tolerant object-shape path; production strict path likely prevents it.
- Labels: `bug`, `host-inbound`, `ha-sync`, `userspace-dataplane`, `security`
- Evidence:
  - `pkg/dataplane/userspace/zones.go:419-453` appends a `ZoneSnapshot{Name, ID}` for every map key, but sets `HostInboundConfigured=true` only when `cfg.Security.Zones[name] != nil`.
  - `userspace-dp/src/policy.rs:646-660` still maps that zone name to ID.
  - `userspace-dp/src/afxdp/forwarding_build/zones.rs:58-62` inserts host-inbound sets only when `host_inbound_configured` is true.
  - `userspace-dp/src/afxdp/forwarding/host_inbound.rs:479-489` returns `true` when no zone host-inbound entry exists.
- Runtime trace:
  1. A lenient/HA-loaded config carries `Security.Zones["trust"] = nil`.
  2. Snapshot still assigns `trust` a valid ID.
  3. Rust policy and zone maps can resolve `trust`, but host-inbound has no entry.
  4. Host-bound traffic from that zone hits `None => true`.
- Why it matters: This reopens the exact "configured zone with no host-inbound stanza admits all" class that #3405 was meant to close, but on tolerant/HA-loaded object shapes.
- Fix direction: Skip nil zones entirely or mark nil-zone snapshots as host-inbound configured with empty token sets; add a tolerant-path regression test.

## 5. Medium Confidence Findings

### C131-M01 - Nil zone entries can shift zone IDs across HA peers

- Severity: Medium
- Confidence: Medium; follows from snapshot numbering but needs HA reproduction.
- Labels: `bug`, `ha`, `zone-id`, `userspace-dataplane`
- Evidence:
  - `pkg/dataplane/userspace/zones.go:413-423` sorts every zone map key and assigns `ID: uint16(i + 1)`.
  - Nil zones consume an ID even though their contents are skipped.
- Runtime trace:
  1. Peer A has `{"dmz": nil, "trust": {...}}`; peer B has only `{"trust": {...}}`.
  2. Peer A assigns `trust` ID 2; peer B assigns `trust` ID 1.
  3. Session/event/policy metadata keyed by numeric zone IDs can diverge across peers.
- Why it matters: HA session sync and event interpretation depend on stable zone ID meaning.
- Fix direction: Filter nil zones before ID assignment, or fail closed on nil zones before snapshot publication.

### C131-M02 - `pre-id-default-policy then log [...]` drops list tails and accepts unknown tokens

- Severity: Medium
- Confidence: High on parser behavior, medium on runtime impact because the feature is documented inert.
- Labels: `bug`, `validation`, `policy-logging`, `vsrx-parity`
- Evidence:
  - `pkg/config/compiler_security.go:218-229` checks only `FindChild("session-init")` and `FindChild("session-close")`.
  - `pkg/config/schema_security.go:768-774` models this as child nodes, not a multi-value list.
- Repro output:
  - Separate lines: `preid=init=true close=true`.
  - Bracket list: `preid=init=true close=false`.
  - `then log bad-tail`: `preid=init=false close=false warnings=[]`.
- Runtime trace:
  1. Operator writes a vSRX-style pre-id default policy logging stanza.
  2. Tail token is dropped or unknown token is accepted as no-op.
  3. Warning text can claim only `session-init`, not the authored list.
- Why it matters: Even if the current userspace dataplane cannot emit pre-ID logs, config validation should not teach operators that typoed security-log config is acceptable.
- Fix direction: Reuse the policy log option parser and strict validation for this surface.

### C131-M03 - The log-option grammar has four independent parsers and no SSOT

- Severity: Medium
- Confidence: High as a refactor diagnosis.
- Labels: `refactor`, `modularity`, `policy-logging`, `tests`
- Evidence:
  - Policy `then log`: `pkg/config/compiler_security.go:710-719`.
  - `default-policy-log`: `pkg/config/compiler_security.go:529-543`.
  - `pre-id-default-policy`: `pkg/config/compiler_security.go:218-229`.
  - `deny` collapsed modifiers: `pkg/config/compiler_security.go:786-825`.
- Runtime trace:
  1. #3141 fixed the collapsed `then deny log` parser.
  2. The sibling log parsers remained structurally different.
  3. This campaign found the same list-tail bug in three other surfaces.
- Why it matters: This is exactly the kind of parser drift that causes security policy to compile differently than the operator authored it.
- Fix direction: Move log-option parsing into `pkg/config/security/policylog` or similar and use it from every security log surface.

### C131-M04 - Host-inbound parsing is spread across schema, compiler, Go lowering, Rust lowering, and nft/docs

- Severity: Medium
- Confidence: High as a refactor diagnosis.
- Labels: `refactor`, `host-inbound`, `modularity`, `vsrx-parity`
- Evidence:
  - Schema: `pkg/config/schema_security.go:93-120`.
  - Compiler: `pkg/config/compiler_security.go:430-455`.
  - Token allowlist/family: `pkg/config/host_inbound_tokens.go`.
  - Go snapshot lowering: `pkg/dataplane/userspace/zones.go`.
  - Rust classifier: `userspace-dp/src/afxdp/forwarding/host_inbound.rs`.
  - Rust build: `userspace-dp/src/afxdp/forwarding_build/zones.rs`.
- Runtime trace:
  1. Schema shape prevented list flattening.
  2. Compiler failed to recover the dropped tail.
  3. Lowering/runtime appeared correct because they never saw the missing token.
- Why it matters: The feature is security-critical and parity-sensitive; bugs can hide at layer boundaries.
- Fix direction: Create a `hostinbound/` module that owns schema construction, parse helpers, validation, snapshot lowering canaries, and generated token tables for Go/Rust parity.

### C131-M05 - `match-policies` still cannot answer the final host-inbound service verdict

- Severity: Medium
- Confidence: Medium; current tests document the limitation, but it is a core firewall diagnostic gap.
- Labels: `feature-gap`, `diagnostics`, `host-inbound`, `vsrx-parity`
- Evidence:
  - `pkg/policymatch/policymatch.go:555-625` returns `HostInboundUnmatched` when no `to-zone junos-host` policy matches.
  - `pkg/policymatch/host_inbound_verdict_msg_3627_test.go:13-24` explicitly says the simulator does not model host-inbound service admission.
- Runtime trace:
  1. Operator asks whether `from-zone untrust to-zone junos-host tcp/22` is allowed.
  2. Tool can say "not governed by transit/default; see host-inbound," but does not evaluate whether `ssh` is allowed on the ingress zone/interface.
- Why it matters: The user asked for a core vSRX firewall audit: proving "deny when denied and allow when allowed" requires a single diagnostic that evaluates host-inbound service admission too.
- Fix direction: Extend the simulator query with ingress interface, protocol, destination port, ICMP type/code, and run the same token classification as the dataplane.

### C131-M06 - RuntimePolicyIDs silently returns a partial map on namespace overflow

- Severity: Medium
- Confidence: Medium; comment says such configs cannot apply, but read-only surfaces can still render partial identity.
- Labels: `diagnostics`, `policy-id`, `observability`
- Evidence:
  - `pkg/dataplane/userspace/policies.go:213-219` documents that `RuntimePolicyIDs` omits offending entries on overflow and callers fall back to raw ordinal.
  - `pkg/dataplane/userspace/policies.go:258-261` is where overflow is detected.
- Runtime trace:
  1. A config with excessive application-set expansion exists in candidate/tolerant state.
  2. `RuntimePolicyIDs` stops early and display callers can fall back to raw ordinal.
  3. Operator may see a display ID that does not match the dataplane/event ID contract.
- Why it matters: Policy ID correlation is operationally critical during a bad apply. The failure mode should be explicit, not fallback identity.
- Fix direction: Return `(map, error)` for diagnostic surfaces, or include an explicit overflow marker in the inventory response.

### C131-M07 - `junos-host` permit logging has no direct dataplane regression test

- Severity: Medium
- Confidence: High as coverage gap.
- Labels: `tests`, `junos-host`, `policy-logging`
- Evidence:
  - `userspace-dp/src/policy_tests.rs:4042-4967` heavily tests `junos-host` deny/permit precedence but does not assert permit log/session metadata propagation.
  - `userspace-dp/src/afxdp/tests.rs` tests deny paths and LocalDelivery behavior, but no test pins host-local `then log` on permit sessions.
- Runtime trace:
  1. The policy evaluator result already contains the log fields.
  2. The LocalDelivery wrapper discards them.
  3. Existing tests still pass because they only assert permit/deny action, not metadata.
- Why it matters: This is why C131-H07 survived.
- Fix direction: Add an AF_XDP local-delivery test where `to-zone junos-host then permit log session-init session-close` installs a session with both log flags and policy ID.

## 6. Low Confidence / Design and Completeness Findings

### C131-L01 - `pkg/config/compiler_security.go` is too broad for a security compiler

- Severity: Low
- Confidence: High as design smell.
- Labels: `refactor`, `modularity`, `security-compiler`
- Evidence:
  - One file compiles SSH known hosts, security log, flow, pre-id-default-policy, zones, policies, screens, NAT-adjacent security options, and session aging.
- Why it matters: Security parser bugs are recurring because unrelated grammar surfaces share one large switch and ad-hoc child/key handling.
- Fix direction: Split into directories such as `pkg/config/security/zones`, `policy`, `logging`, `screen`, and `flow`, with explicit parse helpers for multi-value leaves.

### C131-L02 - `userspace-dp/src/policy.rs` should be split into policy submodules

- Severity: Low
- Confidence: High as performance/correctness maintainability issue.
- Labels: `refactor`, `rust`, `userspace-dataplane`, `performance`
- Evidence:
  - The file owns snapshot parsing, address book resolution, policy indexing, wildcard/global precedence, app parsing, default-policy results, and `junos-host`.
- Why it matters: Hot-path correctness depends on subtle cross-module invariants, but the code is hard to review in isolation.
- Fix direction: Split to `policy/{snapshot.rs,index.rs,eval.rs,apps.rs,address.rs,junos_host.rs}`. Keep hot eval functions small and cache-friendly.

### C131-L03 - `poll_descriptor/mod.rs` local-delivery path needs a `local_delivery/` module

- Severity: Low
- Confidence: High as design smell linked to C131-H07/H08.
- Labels: `refactor`, `rust`, `local-delivery`, `userspace-dataplane`
- Evidence:
  - The same giant loop handles host-inbound admission, lo0 filter, `junos-host`, reject synthesis, session install, conntrack publication, and telemetry.
- Why it matters: The permit metadata loss happened because the `junos-host` helper returned only a deny/drop decision and session install lived far away in the loop.
- Fix direction: Extract a local-delivery pipeline object returning an explicit enum: deny, reject, permit-with-policy-result, permit-without-policy.

### C131-L04 - Bracket-list syntax lacks a generic corpus test for every security multi-value surface

- Severity: Low
- Confidence: High as coverage gap.
- Labels: `tests`, `parser`, `security-compiler`
- Evidence:
  - Existing tests cover many repeated single-value set lines, but the repros here show bracket/single-line lists diverge.
- Why it matters: Junos operators commonly use bracketed set syntax; parser parity cannot be assumed from repeated-line tests.
- Fix direction: Add a table-driven test that exercises repeated-line, bracket-list, and single-line tail forms for host-inbound, policy match addresses/apps, policy log options, default-policy-log, and protocol/address lists.

### C131-L05 - Default-policy-log has no schema/strict-validation test for unknown children

- Severity: Low
- Confidence: High as coverage gap.
- Labels: `tests`, `default-policy`, `validation`
- Evidence:
  - `pkg/config/compiler_default_policy_log_3534_test.go` covers valid flags and inert warnings, but not `bad-tail` or bracket-list forms.
- Why it matters: It allowed C131-H05/H06.
- Fix direction: Add tests that `default-policy-log bad-tail` rejects and `[ session-init session-close ]` sets both flags.

### C131-L06 - Pre-ID default policy warning text is generated from parsed flags, not authored tokens

- Severity: Low
- Confidence: Medium.
- Labels: `diagnostics`, `policy-logging`
- Evidence:
  - Repro `pre-id-default-policy then log [ session-init session-close ]` warns only about `session-init` because the close token was dropped.
- Why it matters: The warning is the only user-visible signal for an inert feature; it should not misquote the authored config.
- Fix direction: Preserve raw option tokens for diagnostics, or reject malformed options before warning construction.

### C131-L07 - Host-inbound tolerant nil-zone behavior lacks a targeted unit test

- Severity: Low
- Confidence: High as coverage gap.
- Labels: `tests`, `host-inbound`, `ha-sync`
- Evidence:
  - `pkg/dataplane/userspace/zones_host_inbound_test.go` covers configured empty/no-stanza zones and interface overrides, but not `Security.Zones[name] == nil`.
- Why it matters: Nil tolerant objects are exactly where the Go/Rust absent-entry contract can regress.
- Fix direction: Add a Go snapshot test and a Rust build/admission test asserting nil zones do not become known/admit-all zones.

### C131-L08 - Host-bound permit-policy identity should be exposed in CLI/API session views

- Severity: Low
- Confidence: Medium; blocked by C131-H08 first.
- Labels: `feature-gap`, `observability`, `junos-host`, `vsrx-parity`
- Evidence:
  - Current LocalDelivery metadata uses `policy_id: 0`; session/conntrack publication therefore cannot surface host-policy identity.
- Why it matters: vSRX operators expect to audit which policy admitted management-plane traffic.
- Fix direction: After stamping the permit result, update session/flow display tests to show the admitting `junos-host` policy.

### C131-L09 - Policy simulator should label host-inbound parity gaps as `vsrx-parity`

- Severity: Low
- Confidence: High as issue-hygiene recommendation.
- Labels: `issue-hygiene`, `vsrx-parity`, `diagnostics`
- Evidence:
  - `pkg/policymatch/host_inbound_verdict_msg_3627_test.go` documents a known simulator limitation.
- Why it matters: User requested vSRX parity issues be clearly labeled in Git. This one directly affects operator parity with Junos "test security policy" style workflows.
- Fix direction: File/label the simulator extension issue as `vsrx-parity`.

### C131-L10 - Host-inbound Rust/Go token parity still relies on hand-maintained mirrors

- Severity: Low
- Confidence: Medium; current tests are strong but the architecture remains drift-prone.
- Labels: `refactor`, `host-inbound`, `codegen`, `vsrx-parity`
- Evidence:
  - Go allowlist/family data lives in `pkg/config/host_inbound_tokens.go`.
  - Rust mirror lives in `userspace-dp/src/afxdp/forwarding/host_inbound.rs`.
  - Docs require coordinated edits across Go, nft, Rust, tests, and docs.
- Why it matters: The feature is parity-heavy and security-sensitive; manual mirror edits are easy to miss.
- Fix direction: Generate Rust token tables and documentation snippets from the Go SSOT or a neutral YAML/JSON table.

### C131-L11 - Default-policy logging lacks an end-to-end AF_XDP session-close test

- Severity: Low
- Confidence: High as coverage gap.
- Labels: `tests`, `default-policy`, `policy-logging`, `userspace-dataplane`
- Evidence:
  - `userspace-dp/src/policy_tests.rs:228-259` validates policy result fields, and Go tests validate snapshot fields, but the parser bug would bypass those if the config source was bracket syntax.
- Why it matters: The actual failure is observed at compile input syntax, then manifests as missing session-close output.
- Fix direction: Add a config-driven integration test that uses `default-policy-log [ session-init session-close ]` and asserts both create and close records.

### C131-L12 - Security parser should expose raw-token validation errors before compile lowering

- Severity: Low
- Confidence: Medium.
- Labels: `refactor`, `validation`, `parser`
- Evidence:
  - Host-inbound and log-option bugs share the same pattern: malformed raw tokens disappear before strict validation runs over compiled structs.
- Why it matters: Compile-lowered structs cannot validate tokens that were dropped.
- Fix direction: Add a raw AST validation pass for security stanzas before lowering, or make `SetPath` preserve all values consistently.

## 7. Suggested Issue Split

1. Fix security flat/bracket list parsing for host-inbound, policy log, default-policy-log, and pre-id-default-policy.
2. Add strict validation for unknown `default-policy-log` and pre-id log tokens.
3. Propagate `junos-host` permit `PolicyEvaluationResult` into local-delivery session metadata.
4. Fix tolerant nil-zone snapshot behavior so nil zones cannot become known/admit-all zones or shift IDs.
5. Extend `match-policies` to evaluate final host-inbound service admission and label as `vsrx-parity`.
6. Add a parser corpus for bracket-list vs repeated-line syntax across security multi-value stanzas.
7. Refactor security compiler/log parsing into smaller modules and shared helpers.
8. Refactor Rust policy/local-delivery modules to make permit metadata propagation explicit.

