# agy Review Audit 144 - IPsec/IKE Passthrough & Host-Inbound Security Bypass

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-144.md`

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
- `/tmp/agy-review-142.md`
- `/tmp/agy-review-143.md`

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. IPsec ESP/AH passthrough bypassing host-inbound service token enforcement
2. Socket delivery thread deadlock under local loopback traffic loops
3. IS-IS packet parser LLC offset overflow hazard on truncated frames

---

## 4. High Confidence Findings

### AGY-144-01 - IPsec ESP/AH Passthrough Bypasses Host-Inbound Service Enforcement

- **Severity**: High
- **Subsystem**: Host-Inbound Security Gate
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/forwarding/host_inbound.rs:341-355](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/forwarding/host_inbound.rs#L341)

```rust
pub fn check_host_inbound(&self, proto: u8) -> bool {
    if proto == PROTO_ESP || proto == PROTO_AH {
        return true;
    }
    self.allowed_protocols.contains(&proto)
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator configures a host-inbound configuration that excludes IPsec traffic.
2. Attacker sends ESP packets directed to the host interface.
3. The host-inbound gate observes `proto == PROTO_ESP` and returns `true`, skipping all per-interface or per-zone service checks.
4. Unconfigured IPsec traffic is delivered to the host stack, exposing the IPsec daemon to untrusted traffic.

- **Irrefutability Proof & Upstream Verification**:
The check hardcodes a bypass for `PROTO_ESP` and `PROTO_AH`, preventing enforcement of specific zone allowlists for VPN endpoints.

- **vSRX Parity & Systems Impact**:
- Unauthorized access to the local IPsec stack, violating Junos zone-isolation parity.

- **Suggested Fix Direction & Labels**:
- Evaluate ESP and AH protocols against explicit host-inbound protocols allowlists.
- Labels: bug, security, host-inbound, vsrx-parity

---

### AGY-144-02 - Socket Delivery Thread Deadlock under Local Loopback Loops

- **Severity**: High
- **Subsystem**: Local Delivery Loop
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/poll_descriptor/mod.rs:1142-1155](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1142)

```rust
pub fn deliver_to_loopback(&mut self, frame: Frame) {
    self.loopback_ring.push(frame);
    self.loopback_condvar.wait(&mut self.buffer_lock);
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Worker 1 handles a packet requiring loopback delivery, pushing it to `loopback_ring` and locking `buffer_lock`.
2. Worker 2 attempts to process an outgoing loopback packet and tries to acquire `buffer_lock`.
3. Both workers stall waiting for each other's locks to release, freezing all dataplane forwarding.

- **Irrefutability Proof & Upstream Verification**:
The thread calls `wait` on a conditional variable while holding a lock shared by the packet queue allocator, causing circular dependency deadlocks.

- **vSRX Parity & Systems Impact**:
- Complete dataplane lockup and traffic freeze.

- **Suggested Fix Direction & Labels**:
- Release the buffer lock before pushing or waiting on loopback delivery queues.
- Labels: bug, deadlock, concurrency

---

### AGY-144-03 - IS-IS Packet Parser LLC Offset Overflow on Truncated Frames

- **Severity**: Medium
- **Subsystem**: IS-IS Frame Parser
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/parser/isis.rs:56-68](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/parser/isis.rs#L56)

```rust
pub fn parse_isis_llc(pkt: &[u8]) -> Option<IsisHeader> {
    let llc_dsap = pkt[14];
    let llc_ssap = pkt[15];
    let isis_offset = 14 + (pkt[16] as usize);
    Some(IsisHeader { offset: isis_offset })
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Router receives a malformed IS-IS multicast frame containing only 16 bytes.
2. Parser reads `pkt[16]` which is out of bounds, triggering a panic.
3. Alternatively, if `pkt[16]` specifies a large offset, `isis_offset` points past the packet size, causing subsequent steps to dereference invalid memory.

- **Irrefutability Proof & Upstream Verification**:
No check is performed on `pkt.len()` before indexing index `16` or verifying that the calculated `isis_offset` fits within the packet length.

- **vSRX Parity & Systems Impact**:
- Worker thread crash (panic) on malformed IS-IS frames.

- **Suggested Fix Direction & Labels**:
- Check if `pkt.len() > 17` and verify `isis_offset < pkt.len()` before returning.
- Labels: bug, parser, multi-cast

---

## 5. Suggested Issue Split

1. **Resolution of AGY-144-01**: Implement dynamic bounds check and validation for IPsec ESP/AH Passthrough Bypasses Host-Inbound Service Enforcement.
2. **Resolution of AGY-144-02**: Implement dynamic bounds check and validation for Socket Delivery Thread Deadlock under Local Loopback Loops.
3. **Resolution of AGY-144-03**: Implement dynamic bounds check and validation for IS-IS Packet Parser LLC Offset Overflow on Truncated Frames.

