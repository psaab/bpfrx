# agy Review Audit 142 - Default-Policy Logging & Option List Grammars

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-142.md`

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
- `/tmp/agy-review-140.md`
- `/tmp/agy-review-141.md`

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. Named policy `then log` bracket list drops `session-close` option
2. Named policy invalid `then log` tail commits if first option is valid
3. default-policy-log list dropping close log option

---

## 4. High Confidence Findings

### AGY-142-01 - Named policy then log [ session-init session-close ] drops session-close

- **Severity**: High
- **Subsystem**: Policy Logging Compiler
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/config/compiler_security.go:710-719](file:///home/ps/git/gemini-xpf/pkg/config/compiler_security.go#L710)

```rust
func parsePolicyLog(node *ASTNode) *PolicyLog {
    // reads only t.Children
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator configures `then log [ session-init session-close ]`.
2. `parsePolicyLog` reads child nodes but does not parse `Keys[1:]` from a flat list, keeping only `session-init`.
3. `buildOneRuleSnapshot` copies only `LogSessionInit = true` and leaves `LogSessionClose = false`.
4. Dataplane emits session create logs but no close logs.

- **Irrefutability Proof & Upstream Verification**:
`schema_security.go:74-90` gives `then log` children but does not model `session-init/session-close` as a multi-value list, causing the parser to ignore list tails.

- **vSRX Parity & Systems Impact**:
- Audit trails miss session-close records despite valid-looking security policy syntax.

- **Suggested Fix Direction & Labels**:
- Add a shared log-option parser that reads both child nodes and `Keys[1:]`.
- Labels: bug, firewall, policy-logging, vsrx-parity

---

### AGY-142-02 - Named policy invalid then log tail commits if the first token is valid

- **Severity**: High
- **Subsystem**: Policy Logging Validation
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/config/compiler_validate_strict.go:3280-3292](file:///home/ps/git/gemini-xpf/pkg/config/compiler_validate_strict.go#L3280)

```rust
func validatePolicyLogActionStrict(pl *PolicyLog) error {
    // only rejects if both session-init and session-close are false
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator writes `then log [ session-init not-a-real-option ]`.
2. Parser drops `not-a-real-option` during compile.
3. Validator sees `SessionInit = true` and accepts the policy.
4. Commit succeeds with no diagnostic warning or error.

- **Irrefutability Proof & Upstream Verification**:
Validator only validates the compiled boolean fields of the `PolicyLog` struct and does not inspect the raw option names.

- **vSRX Parity & Systems Impact**:
- Breaks Junos-style fail-fast config validation on security audit logging controls.

- **Suggested Fix Direction & Labels**:
- Validate raw `then log` tokens against allowed strings before compiling.
- Labels: bug, validation, policy-logging, vsrx-parity

---

### AGY-142-03 - default-policy-log [ session-init session-close ] drops session-close

- **Severity**: High
- **Subsystem**: Default Policy Logging Compiler
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/config/compiler_security.go:529-536](file:///home/ps/git/gemini-xpf/pkg/config/compiler_security.go#L529)

```rust
if initNode := node.FindChild("session-init"); initNode != nil {
		dp.LogSessionInit = true
	}
	if closeNode := node.FindChild("session-close"); closeNode != nil {
		dp.LogSessionClose = true
	}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator configures `default-policy-log [ session-init session-close ]`.
2. Parser processes the bracket list as a child container and only compiles the first element.
3. A default-permit session gets create log metadata but no close log metadata.

- **Irrefutability Proof & Upstream Verification**:
`schema_security.go:155-165` models `default-policy-log` as a child container rather than a multi-value leaf, dropping subsequent elements.

- **vSRX Parity & Systems Impact**:
- Losing close logs on the default policy fallback path hides session duration and byte-close accounting.

- **Suggested Fix Direction & Labels**:
- Parse default-policy-log options using the shared log-option list helper.
- Labels: bug, default-policy, policy-logging, vsrx-parity

---

## 5. Suggested Issue Split

1. **Resolution of AGY-142-01**: Implement dynamic bounds check and validation for Named policy then log [ session-init session-close ] drops session-close.
2. **Resolution of AGY-142-02**: Implement dynamic bounds check and validation for Named policy invalid then log tail commits if the first token is valid.
3. **Resolution of AGY-142-03**: Implement dynamic bounds check and validation for default-policy-log [ session-init session-close ] drops session-close.

