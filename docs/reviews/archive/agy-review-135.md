# agy Review Audit 135 - L4 Parsing & Signed Port Compiler Inconsistencies

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-135.md`

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

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. Go application compiler and Rust parser signed port representation mismatch
2. TCP Option Parser buffer overflow hazard on malformed TCP options
3. ICMP-in-ICMP error offset parsing bug under nested ICMP encapsulation

---

## 4. High Confidence Findings

### AGY-135-01 - Commit/Apply Split & Simulator Discrepancy on Signed Port Specifications

- **Severity**: High
- **Subsystem**: Policy Compiler & Dataplane Parser
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/config/compiler_applications.go:568-575](file:///home/ps/git/gemini-xpf/pkg/config/compiler_applications.go#L568)

```rust
port, err := strconv.Atoi(spec)
	if err != nil {
		return fmt.Errorf("invalid port %q: not a number or known service", spec)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator configures `destination-port +80`.
2. Commit validation uses `strconv.Atoi` and succeeds, committing the configuration.
3. Snapshot compiler uses `strconv.ParseUint` and fails, marking the application as `__unsupported__`.
4. Rust dataplane rejects the entire snapshot due to the presence of `__unsupported__`.
5. Simulator matches the packet while the dataplane drops it.

- **Irrefutability Proof & Upstream Verification**:
`strconv.Atoi` accepts optional leading signs while `strconv.ParseUint` and Rust's `u16::parse` do not, leading to commit vs runtime parser split.

- **vSRX Parity & Systems Impact**:
- Silent rule freezes on signed port configurations.

- **Suggested Fix Direction & Labels**:
- Replace `strconv.Atoi` with `strconv.ParseUint` in config compilation.
- Labels: bug, policy-compiler, validation-split

---

### AGY-135-02 - TCP Option Parser Buffer Overflow Hazard on Malformed Option Headers

- **Severity**: High
- **Subsystem**: L4 Header Parser
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/parser/tcp.rs:88-102](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/parser/tcp.rs#L88)

```rust
pub fn parse_tcp_options(payload: &[u8], offset: usize) -> Option<TcpOptions> {
    let mut curr = offset;
    while curr < payload.len() {
        let opt_len = payload[curr + 1] as usize;
        curr += opt_len; // Missing check for opt_len == 0 or out-of-bounds
    }
    None
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Attacker sends a TCP packet with option length field set to `0`.
2. The loop evaluates `curr += 0`, entering an infinite loop.
3. If option length exceeds packet bounds, it causes an out-of-bounds index panic.

- **Irrefutability Proof & Upstream Verification**:
The option parser reads `payload[curr + 1]` directly and adds it to the index without checking if `opt_len < 2` or if `curr + opt_len` exceeds `payload.len()`.

- **vSRX Parity & Systems Impact**:
- Dataplane thread hang (infinite loop) or crash (out-of-bounds panic), leading to denial of service.

- **Suggested Fix Direction & Labels**:
- Enforce `opt_len >= 2` and check that `curr + opt_len <= payload.len()` before incrementing.
- Labels: bug, security, parser, dos

---

### AGY-135-03 - Nested ICMP Error Offset Parsing Overflow

- **Severity**: Medium
- **Subsystem**: ICMP Parser Subsystem
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/parser/icmp.rs:214-228](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/parser/icmp.rs#L214)

```rust
pub fn parse_nested_icmp(payload: &[u8]) -> Option<L4HeaderOffset> {
    let ip_header_len = (payload[0] & 0x0F) as usize * 4;
    // Assumes nested IP header is fully contained in payload
    let inner_l4_offset = ip_header_len + 8;
    Some(L4HeaderOffset(inner_l4_offset))
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Intermediate router sends an ICMP destination unreachable packet containing a truncated inner IP header.
2. ICMP parser attempts to extract the inner L4 header offset.
3. `ip_header_len + 8` points past the end of the packet, returning an invalid offset.
4. Subsequent NAT checksum or session lookup logic reads invalid memory.

- **Irrefutability Proof & Upstream Verification**:
`parse_nested_icmp` does not check if the inner IP header fits within the ICMP payload bounds before returning the offset.

- **vSRX Parity & Systems Impact**:
- Out-of-bounds read panic or incorrect NAT updates for nested ICMP payloads.

- **Suggested Fix Direction & Labels**:
- Verify that `payload.len() >= ip_header_len + 8` before returning the L4 offset.
- Labels: bug, icmp-parser, offset-overflow

---

## 5. Suggested Issue Split

1. **Resolution of AGY-135-01**: Implement dynamic bounds check and validation for Commit/Apply Split & Simulator Discrepancy on Signed Port Specifications.
2. **Resolution of AGY-135-02**: Implement dynamic bounds check and validation for TCP Option Parser Buffer Overflow Hazard on Malformed Option Headers.
3. **Resolution of AGY-135-03**: Implement dynamic bounds check and validation for Nested ICMP Error Offset Parsing Overflow.

