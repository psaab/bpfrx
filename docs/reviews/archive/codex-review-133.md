# Codex Review Audit 133 - Rust userspace firewall-filter boundary

## Run Metadata

- **Repository**: `/home/ps/git/codex-bpfrx`
- **Reviewer**: codex
- **Base commit inspected**: `acee6f6f7ca4`
- **Sync**: `git pull --rebase` had already fast-forwarded this checkout to `acee6f6f7ca4` during the preceding cycle; working tree was clean before this report.
- **Output path**: `/tmp/codex-review-133.md`
- **Numbering**: `/tmp/agy-review-133.md` exists, but `/tmp/codex-review-133.md` did not. Per the audit instruction, Codex can reuse an AGY number when the Codex number is free.

## Duplicate Suppression

Read/queried the prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` set before counting findings.

Suppressed as already covered:

- `codex-review-131.md`: host-inbound bracket/flat-list drops, strict-validation bypasses, default-policy-log parser holes, nil zone snapshots, runtime policy ID drift.
- `codex-review-132.md`: host-inbound addressless visibility, policy diagnostic selector duplicate/transport issues, REST selector duplicate semantics.
- `agy-review-132.md` through `agy-review-152.md`: repeated three findings on shared session-map mutex contention, cache-line alignment of hot session structures, and O(N) NAT prefix/block remap loops.
- Existing code comments/tests for #2400, #2505, #2506, #2622, #3205, #3297, #3309, #3406 were treated as known context and not counted directly unless the current code now contradicts them or leaves an adjacent helper-boundary gap.

## Module Checklist

Inspected modules/features:

1. `userspace-dp/src/filter/compiler.rs` - Rust snapshot-to-runtime lowering.
2. `userspace-dp/src/filter/engine/matching.rs` - packet match semantics.
3. `userspace-dp/src/filter/mod.rs` - runtime invariants and comments.
4. `userspace-dp/src/protocol/security.rs` - JSON/helper DTO shapes.
5. `userspace-dp/src/filter/tests.rs` - coverage around malformed filters, DSCP, ports, flex, three-color policers.
6. `pkg/dataplane/userspace/filters.go` - Go snapshot builder and tolerant-path warnings.
7. `pkg/config/compiler_validate_strict.go` - strict commit gates for DSCP/ports.
8. `pkg/config/filter_match_resolve.go` - canonical Junos service resolution.
9. `pkg/config/compiler_firewall.go` - firewall-filter parser/lowering.
10. `userspace-dp/src/filter/policer.rs` and related compiler paths - three-color unsupported-shape handling.

Negative result: the core positive cases for all-malformed address/port fail-closed behavior are heavily tested in `userspace-dp/src/filter/tests.rs:4160-4665`, so I did not count "all malformed lists become match-any" as a new issue. The remaining findings are narrower boundary, drift, coverage, and invariant problems.

## High Confidence Findings

### H01 - Rust filter DSCP rewrite masks corrupt wire values into a different valid DSCP

- **Severity**: Medium
- **Confidence**: High
- **Labels**: `bug`, `userspace-dataplane`, `firewall-filter`, `cos`, `vsrx-parity`
- **Evidence**:
  - `userspace-dp/src/protocol/security.rs:212-213`:
    ```rust
    #[serde(rename = "dscp_rewrite", default)]
    pub dscp_rewrite: Option<u8>,
    ```
  - `userspace-dp/src/filter/compiler.rs:620`:
    ```rust
    let dscp_rewrite = snap.dscp_rewrite.map(|value| value & 0x3f);
    ```
  - `pkg/dataplane/userspace/filters.go:179-190` only emits 0..63 from the Go builder and otherwise warns/drops the rewrite.
- **Runtime trace**: A mixed-version or hand-built snapshot sends `"dscp_rewrite": 110`. The Rust compiler accepts the `u8` and rewrites it to `110 & 0x3f == 46` (EF). That is not a fail-closed drop and not a no-op; it actively marks traffic with a different code point from the supplied value.
- **Why it matters**: For CoS, "wrong high-priority marking" is not cosmetic. It can put untrusted traffic into EF queues or violate operator QoS policy. vSRX-style config validation rejects invalid code points; the helper boundary should not reinterpret invalid bytes as valid code points.
- **Fix direction**: Replace masking with an explicit `if value <= 63 { Some(value) } else { warn/drop rewrite or SnapshotIntegrityError }`. Add a Rust regression with `dscp_rewrite: Some(110)` proving it does not become `Some(46)`.

### H02 - Rust filter DSCP match ignores out-of-range wire values instead of rejecting the snapshot

- **Severity**: Medium
- **Confidence**: High
- **Labels**: `bug`, `userspace-dataplane`, `firewall-filter`, `cos`, `test-gap`
- **Evidence**:
  - `userspace-dp/src/protocol/security.rs:188-189`:
    ```rust
    #[serde(rename = "dscp_values", default)]
    pub dscp_values: Vec<u8>,
    ```
  - `userspace-dp/src/filter/compiler.rs:646-647`:
    ```rust
    dscp_bitmap: build_u6_match_bitmap(&snap.dscp_values),
    dscp_match_enabled: !snap.dscp_values.is_empty(),
    ```
  - `userspace-dp/src/filter/compiler.rs:823-830`:
    ```rust
    for value in values {
        if *value < 64 {
            bitmap |= 1u64 << value;
        }
    }
    ```
- **Runtime trace**: A corrupt helper snapshot sends `dscp_values: [46, 110]`. `dscp_match_enabled` is true because the vector is non-empty, but 110 is silently dropped from the bitmap. A term that appears to carry two DSCP selectors actually matches only EF.
- **Why it matters**: The code already treats unrepresentable DSCP tokens as snapshot integrity errors when the Go builder sets `dscp_match_unrepresentable`. Raw out-of-range `u8` values are the same semantic class at the helper boundary, but they are accepted silently.
- **Fix direction**: In `parse_term`, reject any `snap.dscp_values` entry >=64 before building the bitmap, preferably reusing `SnapshotIntegrityError::UnrepresentableFilterDSCP` or a new range-specific variant.

### H03 - DSCP match tests cover builder markers but not raw wire-range corruption

- **Severity**: Medium
- **Confidence**: High
- **Labels**: `test-gap`, `userspace-dataplane`, `firewall-filter`, `cos`
- **Evidence**:
  - `userspace-dp/src/filter/tests.rs:5115-5136` tests only `dscp_match_unrepresentable = true`.
  - `userspace-dp/src/filter/tests.rs` contains many `dscp_values: vec![46]` cases but no `dscp_values: vec![64]` or higher, based on the inspected `rg` results.
- **Runtime trace**: Reverting or preserving `build_u6_match_bitmap`'s silent ignore path is invisible to the existing DSCP tests because none injects the corrupt raw `u8` shape.
- **Why it matters**: The Rust dataplane is a protocol boundary. Tests should prove it rejects invalid numeric payloads as well as builder-emitted marker flags.
- **Fix direction**: Add a Rust test that constructs a `FirewallTermSnapshot` with `dscp_values: vec![64]` and expects a snapshot-integrity error, plus a mixed `[46, 64]` case.

### H04 - Port-except invariant comment in Rust runtime contradicts the actual fail-closed matcher

- **Severity**: Medium
- **Confidence**: High
- **Labels**: `bug`, `docs`, `userspace-dataplane`, `firewall-filter`
- **Evidence**:
  - `userspace-dp/src/filter/mod.rs:159-167` says constrained empty `*-port-except` means "match all ports except {} = match ALL — handled in port_match."
  - `userspace-dp/src/filter/engine/matching.rs:310-316` actually does:
    ```rust
    if constrained && matches!(matcher, PortMatcher::Any) {
        return false;
    }
    ```
  - `userspace-dp/src/filter/tests.rs:7391-7447` asserts unresolved `destination-port-except` must fail closed and fall through to discard.
- **Runtime trace**: A maintainer reading `mod.rs` can "fix" `port_match` back to match-all for except-empty, directly reintroducing the #3205 fail-open that the tests now defend against.
- **Why it matters**: This is an invariant comment in a hot-path runtime struct, not stale user docs. It documents the opposite security rule from the code.
- **Fix direction**: Update `mod.rs` to match `matching.rs`: constrained `PortMatcher::Any` means every configured token failed to parse, and both positive and except forms must match nothing.

### H05 - Go compiler comment still says unresolved port-except fails open in dataplane, but Rust now fails closed

- **Severity**: Low
- **Confidence**: High
- **Labels**: `docs`, `firewall-filter`, `userspace-dataplane`
- **Evidence**:
  - `pkg/config/compiler_firewall.go:306-312`:
    ```go
    // record unresolved tokens — an unresolved except port that slips
    // through fails OPEN (matches all ports) in the dataplane.
    ```
  - Current Rust `port_match` at `userspace-dp/src/filter/engine/matching.rs:310-316` fails closed for constrained empty port matchers.
- **Runtime trace**: The strict gate still matters, but the fallback behavior described in the Go compiler is no longer true after #3205.
- **Why it matters**: This cross-language stale comment can lead future reviewers to overstate runtime exposure or add conflicting "fixes" in the wrong layer.
- **Fix direction**: Reword to "pre-#3205 failed open; the Rust dataplane now fails closed, and the strict gate keeps the operator-visible commit contract."

### H06 - Rust filter compiler silently positive-wins impossible positive+except port snapshots

- **Severity**: Low
- **Confidence**: High
- **Labels**: `correctness`, `userspace-dataplane`, `firewall-filter`, `vsrx-parity`
- **Evidence**:
  - `userspace-dp/src/filter/compiler.rs:551-558` documents positive-wins.
  - `userspace-dp/src/filter/compiler.rs:559-572` selects the except list only when all positive specs are not real.
  - `pkg/config/compiler_validate_strict.go:4258-4321` rejects this shape at commit because Junos treats positive and `-except` ports as mutually exclusive.
- **Runtime trace**: A direct helper snapshot with `destination_ports: ["22"]` and `destination_ports_except: ["443"]` compiles and ignores the except list. That is narrower than match-all but still not the operator-authored term.
- **Why it matters**: The helper boundary already fails closed for unrepresentable ICMP/DSCP/flex/protocol shapes. This impossible Junos shape is only warned by the Go builder on lenient load, but direct JSON/protocol input gets no integrity error.
- **Fix direction**: Consider returning a snapshot-integrity error for both-positive-and-except at the Rust boundary. If tolerant mode must preserve traffic, make the status explicit rather than silent positive-wins.

## Medium Confidence Findings

### M01 - `dscp_rewrite` lacks an unrepresentable marker unlike `dscp_values`

- **Severity**: Low
- **Confidence**: Medium
- **Labels**: `design`, `cos`, `userspace-dataplane`
- **Evidence**:
  - `userspace-dp/src/protocol/security.rs:272-284` defines `dscp_match_unrepresentable` and explicitly says rewrite is not carried there.
  - `pkg/dataplane/userspace/filters.go:171-190` warns and drops bad rewrites on the Go side.
  - Rust wire field remains a bare `Option<u8>` at `userspace-dp/src/protocol/security.rs:212-213`.
- **Runtime trace**: The Go path can warn on a bad string rewrite, but once the snapshot crosses the protocol boundary the Rust side cannot distinguish "valid rewrite 46" from "invalid raw byte that masked to 46".
- **Why it matters**: Boundary contracts should not depend on only one producer. This platform is now intentionally userspace-dataplane-first; the Rust helper should defend itself.
- **Fix direction**: Add a `dscp_rewrite_unrepresentable` marker or range-check the raw field in Rust and surface a structured status/warning.

### M02 - Partial malformed port lists are intentionally narrowed, but the security contract is not separated from commit validation

- **Severity**: Medium
- **Confidence**: Medium
- **Labels**: `correctness`, `firewall-filter`, `userspace-dataplane`, `vsrx-parity`
- **Evidence**:
  - `userspace-dp/src/filter/compiler.rs:573-581` uses `filter_map(parse_port_spec)` and drops malformed tokens from a selected list.
  - `userspace-dp/src/filter/engine/matching.rs:291-316` only detects the all-malformed `PortMatcher::Any` case, not "some parsed, some dropped."
  - `pkg/config/compiler_validate_strict.go:4137-4204` rejects unknown ports on commit.
- **Runtime trace**: A tolerant or hand-built snapshot with `destination_ports: ["22", "bad"]` compiles to a matcher for only port 22. If the term is `then discard`, traffic that should have matched the bad intended port falls through. If the term is `then accept`, only the valid part is accepted.
- **Why it matters**: The strict Go commit gate blocks fresh configs, but the Rust boundary accepts a semantically partial term. vSRX would reject the whole invalid match value rather than narrow it silently.
- **Fix direction**: Track `dropped_any_port_spec` while parsing and reject the snapshot if any non-empty selected port spec fails to parse, not just when all fail.

### M03 - Rust port parser accepts only a tiny fallback service-name set

- **Severity**: Low
- **Confidence**: Medium
- **Labels**: `feature-completeness`, `firewall-filter`, `userspace-dataplane`, `vsrx-parity`
- **Evidence**:
  - Rust fallback table at `userspace-dp/src/filter/compiler.rs:764-780` recognizes only http/https/ssh/telnet/ftp/ftp-data/smtp/dns/pop3/imap/snmp/ntp/bgp/ldap/syslog.
  - Go canonical Junos table at `pkg/config/filter_match_resolve.go:84-175` includes many more names such as `domain`, `tacacs-ds`, `kerberos-sec`, `rip`, `radius`, `nfsd`, etc.
- **Runtime trace**: Normal Go snapshots are numeric, so this is a mixed-version/hand-built boundary issue. A direct snapshot with `destination_ports_except: ["domain"]` goes constrained+Any and fails closed, while Go-resolved `domain` would become `53`.
- **Why it matters**: The fallback parser is a second service-name table with lower vSRX parity than the Go table. That is long-term drift risk.
- **Fix direction**: Either delete symbolic fallback support from Rust and require numeric-only snapshots, or generate/share a canonical service table with a drift test.

### M04 - Rust port parser does not trim or lowercase fallback symbolic ports

- **Severity**: Low
- **Confidence**: Medium
- **Labels**: `correctness`, `userspace-dataplane`, `firewall-filter`
- **Evidence**:
  - `userspace-dp/src/filter/compiler.rs:760-781` matches `spec` directly.
  - Go resolver trims and lowercases at `pkg/config/filter_match_resolve.go:222-239`.
- **Runtime trace**: A direct snapshot carrying `" SSH "` or `"SSH"` fails Rust parsing while the Go commit path would normalize it to 22. Depending on all-vs-partial malformed state, the term either fails closed or narrows.
- **Why it matters**: If Rust keeps a fallback symbolic parser, it should have the same normalization semantics as the Go resolver.
- **Fix direction**: Normalize with `trim()` + lowercase before matching, or reject all non-numeric symbolic wire values explicitly.

### M05 - Partial malformed address lists are deliberately kept, but there is no operator-visible marker for dropped entries

- **Severity**: Low
- **Confidence**: Medium
- **Labels**: `observability`, `firewall-filter`, `userspace-dataplane`
- **Evidence**:
  - `userspace-dp/src/filter/compiler.rs:483-492` calls `parse_address` for every token.
  - `userspace-dp/src/filter/compiler.rs:739-757` drops parse failures without returning a reason.
  - `userspace-dp/src/filter/tests.rs:4627-4661` explicitly asserts one valid plus one malformed address keeps the valid scope.
- **Runtime trace**: A tolerant snapshot with `source_addresses: ["203.0.113.0/24", "garbage"]` creates a term scoped only to `203.0.113.0/24`. No status records that one configured entry vanished.
- **Why it matters**: For accept/discard filters this is a real semantic change, even if it is a deliberate fail-safe compromise. Operators need a diagnostic that the helper dropped part of a match set.
- **Fix direction**: Add a non-fatal integrity warning/status for partial-malformed address lists, or reject any malformed non-empty address token at the Rust boundary.

### M06 - Address parser does not trim or normalize raw address tokens

- **Severity**: Low
- **Confidence**: Medium
- **Labels**: `correctness`, `firewall-filter`, `userspace-dataplane`
- **Evidence**:
  - `userspace-dp/src/filter/compiler.rs:739-757` uses `prefix.parse::<IpNet>()`, `prefix.parse::<Ipv4Addr>()`, and `prefix.parse::<Ipv6Addr>()` on the raw string.
  - `addr_is_real` at `userspace-dp/src/filter/compiler.rs:727-729` treats `" any "` as real, not the `any` placeholder.
- **Runtime trace**: A snapshot with `source_addresses: [" 203.0.113.1 "]` fails parsing and becomes all-malformed/partial-malformed depending on siblings. `" any "` becomes a real malformed constraint rather than match-any.
- **Why it matters**: Go normally emits clean values, but helper-boundary code should not let whitespace alter firewall behavior.
- **Fix direction**: Trim before placeholder checks and parsing, or make invalid whitespace an explicit snapshot-integrity error.

### M07 - Three-color unsupported policer snapshots replace the previous good runtime with fail-closed drop

- **Severity**: Medium
- **Confidence**: Medium
- **Labels**: `correctness`, `cos`, `userspace-dataplane`, `vsrx-parity`
- **Evidence**:
  - `userspace-dp/src/filter/compiler.rs:319-337` builds a runtime even when `build_three_color_policer_state` returns `None`, using `ThreeColorPolicerState::fail_closed`.
  - `userspace-dp/src/filter/compiler.rs:367-398` returns `None` for unsupported shape, including non-color-blind or non-discard then-action.
  - `userspace-dp/src/filter/tests.rs:1214-1405` asserts unsupported snapshots "must still link a fail-closed runtime" and matching traffic drops.
- **Runtime trace**: A refresh with an unsupported three-color shape does not reject the whole snapshot and preserve the previous good state; it installs an unsupported runtime that drops matching traffic.
- **Why it matters**: Fail-closed is defensible for security, but it can also blackhole production traffic during mixed-version or partial-feature rollout. For router appliances, "preserve previous good dataplane state and alarm" is often safer than "install drop-all runtime" for unsupported CoS metadata.
- **Fix direction**: Revisit whether unsupported three-color policers should be `SnapshotIntegrityError` so reconcile keeps the old state. If the current behavior is intentional, expose a very explicit status/alarm.

### M08 - Three-color unsupported shape has status, but no compile-time reason code for why it failed

- **Severity**: Low
- **Confidence**: Medium
- **Labels**: `observability`, `cos`, `userspace-dataplane`
- **Evidence**:
  - `userspace-dp/src/filter/compiler.rs:397-398` reduces all unsupported shapes to a boolean predicate.
  - `userspace-dp/src/filter/policer.rs:329-334` reports mode `"unsupported"` but not the unsupported field.
  - Tests at `userspace-dp/src/filter/tests.rs:1214-1405` cover multiple unsupported input shapes but assert the same unsupported/drop result.
- **Runtime trace**: `color_blind=false`, unknown mode, and unsupported then-action all collapse into the same runtime status. An operator cannot tell whether to fix color awareness, mode spelling, or action support.
- **Why it matters**: vSRX-style operational troubleshooting depends on reasoned commit/runtime errors, not generic "unsupported."
- **Fix direction**: Carry an enum reason into `ThreeColorPolicerRuntime` status and log it when fail-closed runtime is installed.

### M09 - `FilterState` feature flags do not expose invalid/partial-lowered helper state

- **Severity**: Low
- **Confidence**: Medium
- **Labels**: `observability`, `modularity`, `userspace-dataplane`
- **Evidence**:
  - `userspace-dp/src/filter/compiler.rs:112-128` computes flags like `has_dscp_match_terms`, `has_per_packet_l4_match_terms`, and `has_three_color_policer_terms`.
  - No corresponding flag tracks "partial malformed values dropped" or "invalid numeric helper values seen."
- **Runtime trace**: A term with `[46, 110]` DSCP values and a term with clean `[46]` both produce the same runtime feature flags.
- **Why it matters**: Reconcile/status code has no cheap way to alarm on downgraded filter semantics after parse.
- **Fix direction**: Return a richer parse result with warnings alongside `FilterState`, or include boundary-integrity counters/status in the helper protocol.

### M10 - `filter/mod.rs` comments are stale around port-except empty-set behavior

- **Severity**: Low
- **Confidence**: Medium
- **Labels**: `docs`, `test-gap`, `userspace-dataplane`
- **Evidence**:
  - Same contradiction as H04, specifically `userspace-dp/src/filter/mod.rs:164-166` vs `userspace-dp/src/filter/engine/matching.rs:291-316`.
- **Runtime trace**: Tests protect runtime behavior now, but the model comments a future implementor reads are wrong.
- **Why it matters**: This file is the struct/invariant home. Stale invariants are not harmless in a security appliance; they encode the wrong mental model.
- **Fix direction**: Update the comments and add a small test assertion message that cites the current invariant by name.

## Low Confidence / Triage Findings

### L01 - Move filter snapshot integrity into a dedicated module

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `refactor`, `modularity`, `userspace-dataplane`
- **Evidence**: `userspace-dp/src/filter/compiler.rs` now contains protocol resolution, address parsing, port parsing, DSCP validation, flex validation, three-color lowering, interface binding, and filter-state construction in one file.
- **Risk**: The current file mixes parser backstops with runtime assembly, making boundary-validation gaps like DSCP range masking easy to miss.
- **Fix direction**: Split to `filter/compiler/{state.rs,term.rs,integrity.rs,ports.rs,addresses.rs,dscp.rs,three_color.rs}` rather than adding more `filter_foo.rs` files.

### L02 - Add a corrupt-snapshot fuzz/proptest target for Rust filter lowering

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `test-gap`, `fuzzing`, `userspace-dataplane`, `firewall-filter`
- **Evidence**: The tests have many named regressions, but no property target that mutates raw snapshot fields across ports/DSCP/addresses/flex.
- **Risk**: Every new helper field repeats the same failure mode: Go validates, Rust trusts or partially drops.
- **Fix direction**: Add proptest cases that generate invalid-but-deserializable `FirewallTermSnapshot` values and assert either a snapshot-integrity error or a declared warning.

### L03 - Generate the Junos service-name table for Go and Rust from one source

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `refactor`, `vsrx-parity`, `firewall-filter`
- **Evidence**: Go has the canonical table at `pkg/config/filter_match_resolve.go:84-175`; Rust has a tiny fallback in `userspace-dp/src/filter/compiler.rs:764-780`.
- **Risk**: Even if Rust eventually becomes numeric-only, the existing fallback creates a false sense of parity.
- **Fix direction**: Generate both from `data/junos/services.yaml`, or delete the Rust symbolic fallback and assert numeric-only snapshots.

### L04 - Define a Rust helper-boundary validation policy by field class

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `architecture`, `userspace-dataplane`, `security`
- **Evidence**: Protocol/flex/ICMP/DSCP-match reject; DSCP-rewrite masks; partial address/port drops; positive+except ports positive-win; three-color unsupported installs drop runtime.
- **Risk**: These are individually defensible choices, but the policy is inconsistent and hard to review.
- **Fix direction**: Document field classes: reject snapshot, preserve old state, install fail-closed runtime, warn-and-drop side effect, or silently normalize. Then make code match that policy.

### L05 - Add Go/Rust DTO range canaries for `u8` fields that are semantically narrower

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `test-gap`, `protocol`, `userspace-dataplane`
- **Evidence**: `dscp_values` and `dscp_rewrite` are `u8` on the wire but semantically 0..63.
- **Risk**: Rust type safety is not enough when protocol fields have tighter semantic ranges than their storage type.
- **Fix direction**: Add table-driven tests for every `u8` helper field whose valid set is not 0..255.

### L06 - Treat partial malformed filter scopes as warning-producing parse results

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `observability`, `firewall-filter`, `userspace-dataplane`
- **Evidence**: Tests explicitly allow partial malformed address retention at `userspace-dp/src/filter/tests.rs:4627-4661`.
- **Risk**: The behavior is intentional, but invisible. Operators see neither commit error on tolerant path nor helper warning.
- **Fix direction**: Return `FilterParseWarnings` from the compiler and expose counters/logs without changing packet behavior immediately.

### L07 - Add regression tests for direct mixed positive+except port snapshots

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `test-gap`, `firewall-filter`, `vsrx-parity`
- **Evidence**: Config tests cover commit rejection (`pkg/config/firewall_port_except_mutex_3297_test.go`), and Rust tests cover unresolved except-only (#3205), but I did not find a direct Rust test for positive+except in the same raw snapshot.
- **Risk**: The Rust fallback behavior is security-relevant and should be pinned whether it remains positive-wins or changes to integrity error.
- **Fix direction**: Add a Rust test with both `destination_ports` and `destination_ports_except` present, with expected behavior explicitly named.

### L08 - Add a filter compiler warning/status path independent of `slog` in Go

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `observability`, `modularity`, `userspace-dataplane`
- **Evidence**: Go builder warnings at `pkg/dataplane/userspace/filters.go:137-148` and `171-190` do not become structured helper state.
- **Risk**: Cluster/HA peers and REST/CLI status cannot reliably surface which terms were downgraded.
- **Fix direction**: Include warning structs in the userspace helper publish/status protocol.

### L09 - Add explicit vSRX parity issue labels for helper-boundary filter semantics

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `process`, `vsrx-parity`
- **Evidence**: Several findings here are not "missing a keyword"; they are "invalid Junos shapes should reject like vSRX rather than normalize/downgrade."
- **Risk**: Without a `vsrx-parity` label, these get triaged as ordinary cleanup and the firewall contract remains drift-prone.
- **Fix direction**: Label DSCP range, positive+except, service-name table, and unsupported three-color behavior issues as `vsrx-parity` when opened.

### L10 - Comment in `compiler_validate_strict.go` still says tolerant DSCP match widens

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `docs`, `firewall-filter`, `cos`
- **Evidence**: `pkg/config/compiler_validate_strict.go:4693-4697` says on tolerant path "the snapshot builder drops the bad token independently (a leniently-loaded match widens...)".
- **Risk**: Current `pkg/dataplane/userspace/filters.go:159-169` sets `DSCPMatchUnrepresentable`, and Rust rejects via `userspace-dp/src/filter/compiler.rs:460-466`. The comment appears stale for match values, though still true historically and for rewrite no-op.
- **Fix direction**: Reword to distinguish pre-fix behavior, current Rust fail-closed marker for match, and warning/no-op behavior for rewrite.

### L11 - `parse_port_spec` and Go resolver have diverged range-name behavior

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `correctness`, `firewall-filter`, `userspace-dataplane`
- **Evidence**:
  - Go `resolveFilterPort` handles whole-spec service names before splitting ranges (`pkg/config/filter_match_resolve.go:251-260`), then supports named ranges like `http-https`.
  - Rust `parse_port_spec` whole-name table is tiny and then splits on `-` at `userspace-dp/src/filter/compiler.rs:782-789`.
- **Risk**: Direct snapshots with Junos names/ranges supported by Go can be rejected or partially dropped by Rust.
- **Fix direction**: Numeric-only snapshots or generated shared parser.

### L12 - Three-color unsupported-shape tests assert drop but not status reason completeness

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `test-gap`, `cos`, `userspace-dataplane`
- **Evidence**: `userspace-dp/src/filter/tests.rs:1214-1405` checks mode `"unsupported"` and drop behavior for several shapes.
- **Risk**: Future improvements could still lump all reasons together and pass existing tests.
- **Fix direction**: Once reason enums exist, add one test per unsupported field verifying the surfaced reason.

### L13 - Boundary validation is split across Go strict, Go tolerant, and Rust helper paths without a single matrix

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `docs`, `architecture`, `test-gap`
- **Evidence**: DSCP, ICMP, ports, flex, address, action, and three-color each have separate historical comments and tests spread across Go/Rust files.
- **Risk**: Reviewers repeatedly have to rediscover which layer owns strict reject vs tolerant warning vs helper reject.
- **Fix direction**: Add `docs/filter-boundary-contract.md` or a table in `userspace-dp/src/FEATURES.md` with one row per field.

### L14 - Performance: filter compiler repeatedly allocates vectors for parse/drop paths

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `performance`, `userspace-dataplane`
- **Evidence**: `parse_term` builds separate `Vec`s for addresses, ports, protocols, and terms on each snapshot refresh.
- **Risk**: This is not packet hot path, but large configs with thousands of terms can cause avoidable refresh latency and memory churn.
- **Fix direction**: After correctness is settled, pre-size address/port vectors and consider returning small arrays for common one-entry cases.

### L15 - Runtime comment says port empty-except mirrors address empty-except, but tests prove the opposite

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `docs`, `userspace-dataplane`, `firewall-filter`
- **Evidence**:
  - Address empty except intentionally matches all for cross-family/empty prefix-lists in `userspace-dp/src/filter/engine/matching.rs:239-249`.
  - Port empty except intentionally does not invert in `userspace-dp/src/filter/engine/matching.rs:291-316`.
  - `userspace-dp/src/filter/mod.rs:159-167` still reads as if port behaves like address.
- **Risk**: This subtle address-vs-port distinction is exactly where previous fail-open bugs lived.
- **Fix direction**: Add a short invariant block contrasting address empty-except and port malformed-except behavior.

### L16 - Rust filter protocol should document producer trust assumptions

- **Severity**: Low
- **Confidence**: Low
- **Labels**: `docs`, `protocol`, `userspace-dataplane`
- **Evidence**: `userspace-dp/src/protocol/security.rs` has rich per-field comments but not a top-level statement of whether deserialized snapshots are trusted only from current Go or must be robust to older/malformed producers.
- **Risk**: Without that statement, maintainers disagree whether direct corrupt `u8` DSCP values are a blocker or out-of-contract input.
- **Fix direction**: Add a top-level protocol contract: "Rust must reject or explicitly warn on any deserializable snapshot that violates semantic ranges, because helper input can come from mixed-version HA/tolerant load."

