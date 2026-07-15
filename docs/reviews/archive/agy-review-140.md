# agy Review Audit 140 - Host-Inbound CLI Selector Validation & typos

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-140.md`

---

## 2. Duplicate Suppression Summary

Prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` reports were scanned for duplicates to ensure zero-duplicate reporting. Specifically, the following historical reviews were cross-referenced and suppressed:
- `/tmp/agy-review-001.md`
- `/tmp/agy-review-002.md`
- `/tmp/agy-review-003.md`
- `/tmp/agy-review-004.md`
- `/tmp/agy-review-005.md`
- `/tmp/agy-review-121.md`
- `/tmp/agy-review-122.md`
- `/tmp/agy-review-124.md`
- `/tmp/agy-review-125.md`
- `/tmp/agy-review-126.md`
- `/tmp/agy-review-127.md`
- `/tmp/agy-review-128.md`
- `/tmp/agy-review-129.md`
- `/tmp/agy-review-130.md`
- `/tmp/agy-review-131.md`
- `/tmp/agy-review-132.md`
- `/tmp/agy-review-133.md`
- `/tmp/agy-review-134.md`
- `/tmp/agy-review-135.md`
- `/tmp/agy-review-136.md`
- `/tmp/agy-review-137.md`
- `/tmp/agy-review-138.md`
- `/tmp/agy-review-139.md`

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. Host-inbound flat list syntax drops every value after the first
2. Host-inbound invalid bracket list tail bypasses strict validation
3. CLI `test policy` silently wildcarding selectors when value is missing

---

## 4. High Confidence Findings

### AGY-140-01 - Host-inbound flat/bracket list syntax drops every value after the first

- **Severity**: High
- **Subsystem**: Host-inbound Compiler
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/config/schema_security.go:109-120](file:///home/ps/git/gemini-xpf/pkg/config/schema_security.go#L109)

```rust
// pkg/config/compiler_security.go:430-455
func parseHostInboundNode(hit *ASTNode) []string {
    // parses only hit.Children; it never reads hit.Keys[1:]
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator configures `system-services [ ssh ping ]`.
2. Flat-set parser strips brackets, but `SetPath` does not mark the remaining tokens as values for the same leaf.
3. `parseHostInboundNode` sees only the first child `ssh`.
4. `buildZoneSnapshots` sends only `ssh` to Rust.
5. ICMP echo (ping) that vSRX syntax intended to allow is denied at the dataplane.

- **Irrefutability Proof & Upstream Verification**:
`ast_edit.go` only collapses trailing bracket-list values when `childSchema.multi` is true. `system-services` is modeled as a child container, dropping subsequent values.

- **vSRX Parity & Systems Impact**:
- Intended permitted host-inbound services/protocols are silently lost, breaking management access.

- **Suggested Fix Direction & Labels**:
- Teach `parseHostInboundNode` to read `hit.Keys[1:]` exactly like policy match address/application parsing.
- Labels: bug, host-inbound, vsrx-parity

---

### AGY-140-02 - Host-inbound invalid bracket-list tail bypasses strict validation

- **Severity**: High
- **Subsystem**: Host-inbound Validation
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/config/compiler_validate_strict.go:6111-6122](file:///home/ps/git/gemini-xpf/pkg/config/compiler_validate_strict.go#L6111)

```rust
func validateHostInboundStrict(hib *HostInbound) error {
    // validates only the compiled hib.SystemServices / hib.Protocols slices
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator mistypes the second token in a list: `system-services [ ssh sssh ]`.
2. Parser drops the second token `sssh` because it's after the first element.
3. Strict validation runs over the compiled struct which only contains `ssh`.
4. Commit succeeds with no errors or warnings, and the typoed service is silently ignored.

- **Irrefutability Proof & Upstream Verification**:
`validateHostInboundStrict` validates the compiled slices, but the parser drops tail tokens before validation runs, hiding the error.

- **vSRX Parity & Systems Impact**:
- Typos in config commit successfully with a narrower policy than authored, creating operational gaps.

- **Suggested Fix Direction & Labels**:
- Validate raw bracket-list tokens against the allowed services set before compiling.
- Labels: bug, validation, security, host-inbound, vsrx-parity

---

### AGY-140-03 - Local test policy silently wildcards selectors when value is missing

- **Severity**: High
- **Subsystem**: test-policy CLI Command
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/cli/cli_request.go:184-192](file:///home/ps/git/gemini-xpf/pkg/cli/cli_request.go#L184)

```rust
case "source-port":
			if i+1 < len(args) {
				srcPort, _ = strconv.Atoi(args[i+1])
			}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator executes `test policy from-zone trust to-zone untrust source-port`.
2. Parser parses `source-port` but finds no trailing element, skipping assignment.
3. `srcPort` remains `0` (wildcard).
4. Command returns matching policy rules for any source port, rather than returning an error.

- **Irrefutability Proof & Upstream Verification**:
The parsing loop checks `i+1 < len(args)` but fails to raise an error if false, silently falling back to default/wildcard values.

- **vSRX Parity & Systems Impact**:
- Fail-open parser behaviors make policy validation untrustworthy during incident response.

- **Suggested Fix Direction & Labels**:
- Raise an error if a parsed selector flag is missing its value token.
- Labels: bug, security, firewall-policy, cli, test-policy

---

## 5. Suggested Issue Split

1. **Resolution of AGY-140-01**: Implement dynamic bounds check and validation for Host-inbound flat/bracket list syntax drops every value after the first.
2. **Resolution of AGY-140-02**: Implement dynamic bounds check and validation for Host-inbound invalid bracket-list tail bypasses strict validation.
3. **Resolution of AGY-140-03**: Implement dynamic bounds check and validation for Local test policy silently wildcards selectors when value is missing.

