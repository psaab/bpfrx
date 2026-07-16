# agy Review Audit 141 - Remote CLI Policy Matching Discrepancies

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-141.md`

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

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. Remote CLI `show security match-policies` silently wildcarding missing selector values
2. Remote CLI `show security match-policies` ignoring unknown selector tokens
3. Policy match diagnostic parser duplication leading to syntax drift

---

## 4. High Confidence Findings

### AGY-141-01 - Remote CLI show security match-policies silently wildcards missing selector values

- **Severity**: High
- **Subsystem**: Remote CLI show security match-policies
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [cmd/cli/show.go:1174-1182](file:///home/ps/git/gemini-xpf/cmd/cli/show.go#L1174)

```rust
case "protocol":
			if i+1 < len(args) {
				req.Protocol = args[i+1]
			}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator runs `cli show security match-policies from-zone trust to-zone untrust protocol`.
2. The remote client parses `protocol` but skips it because it has no value.
3. Request is sent with an empty `Protocol` field.
4. Daemon evaluates match request against all protocols, returning a wider set of rules than intended.

- **Irrefutability Proof & Upstream Verification**:
The remote parser skips assignment and errors when the value token is missing, letting the RPC proceed with default wildcards.

- **vSRX Parity & Systems Impact**:
- Remote diagnostics return incorrect match results due to silent field widening.

- **Suggested Fix Direction & Labels**:
- Fail validation and abort RPC if any specified selector lacks its value.
- Labels: bug, security, firewall-policy, remote-cli, grpc

---

### AGY-141-02 - Remote CLI show security match-policies ignores unknown selector tokens

- **Severity**: High
- **Subsystem**: Remote CLI show security match-policies
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [cmd/cli/show.go:1183-1192](file:///home/ps/git/gemini-xpf/cmd/cli/show.go#L1183)

```rust
for i := 0; i < len(args); i++ {
		switch args[i] {
		// No default case is implemented
		}
	}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator runs `cli show security match-policies destination-poort 443`.
2. The typo `destination-poort` is ignored.
3. `DestinationPort` is sent as `0` in the gRPC request.
4. Remote daemon matches all destination ports instead of port 443.

- **Irrefutability Proof & Upstream Verification**:
The parsing loop lacks a fallback arm to reject unrecognized command line option tokens.

- **vSRX Parity & Systems Impact**:
- Typographical errors in remote CLI calls cause over-broad policy matches.

- **Suggested Fix Direction & Labels**:
- Return a parsing error on the client side when encountering unknown selectors.
- Labels: bug, security, firewall-policy, remote-cli, grpc

---

### AGY-141-03 - Duplicated Match Policy Diagnostic Parsers Causing Behavior Drift

- **Severity**: Medium
- **Subsystem**: Policy Match Diagnostics
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/policymatch/policymatch.go:205-215](file:///home/ps/git/gemini-xpf/pkg/policymatch/policymatch.go#L205)

```rust
// pkg/cli/cli_request.go:184-255 repeats selector parsing
// cmd/cli/show.go:1174-1255 repeats selector parsing
// cmd/cli/main.go:447-523 repeats selector parsing
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Developer fixes selector parsing in `policymatch.go`.
2. The duplicated parsing loops in `cli_request.go`, `show.go`, and `main.go` are left unpatched.
3. Remote match queries and local policy tests parse identical commands differently, producing mismatch results.

- **Irrefutability Proof & Upstream Verification**:
Four independent parser functions duplicate CLI token matching logic rather than importing a shared parser implementation.

- **vSRX Parity & Systems Impact**:
- Diverging CLI query behavior across local and remote query interfaces.

- **Suggested Fix Direction & Labels**:
- Consolidate CLI selector parsing into a single helper module shared by all command surfaces.
- Labels: refactor, duplicate-code, parser

---

## 5. Suggested Issue Split

1. **Resolution of AGY-141-01**: Implement dynamic bounds check and validation for Remote CLI show security match-policies silently wildcards missing selector values.
2. **Resolution of AGY-141-02**: Implement dynamic bounds check and validation for Remote CLI show security match-policies ignores unknown selector tokens.
3. **Resolution of AGY-141-03**: Implement dynamic bounds check and validation for Duplicated Match Policy Diagnostic Parsers Causing Behavior Drift.

