# agy Review Audit 143 - Reject Reply Synthesis & Rate Limiting Contention

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-143.md`

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

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. Single global rate-limit bucket for TCP Reset / ICMP Reject allowing cross-zone starvation
2. Reject reply generation building full packet before evaluating rate limit budget
3. output-filter-dropped rejects silently recorded as successful transmissions

---

## 4. High Confidence Findings

### AGY-143-01 - Single Global Rate-Limit Bucket Starvation Hazard for Local Reject Responses

- **Severity**: Medium
- **Subsystem**: Reject Rate Limiter
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/reject.rs:74-88](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/reject.rs#L74)

```rust
pub fn acquire_reject_token(&mut self) -> bool {
    self.global_bucket.acquire(1)
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Attacker floods interface `ge-0/0/0.0` in Untrust with packets matching a reject policy.
2. The global rate limiter depletes all available reject tokens.
3. Valid traffic on interface `ge-0/0/1.0` in Trust hits a reject policy.
4. The system fails to generate TCP Reset or ICMP unreachable packets for Trust traffic because the global token pool is exhausted, leading to silent drops.

- **Irrefutability Proof & Upstream Verification**:
A single global token bucket is shared across all interfaces and zones for rate-limiting reject packet generation.

- **vSRX Parity & Systems Impact**:
- Denial of service and cross-zone starvation of reject response packets.

- **Suggested Fix Direction & Labels**:
- Implement per-zone or per-interface token buckets for reject rate limiting.
- Labels: bug, reject-handler, starvation

---

### AGY-143-02 - Reject Reply Packet Allocation Performed Before Evaluating Rate Limiter

- **Severity**: Medium
- **Subsystem**: Reject Packet Generator
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/reject.rs:114-128](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/reject.rs#L114)

```rust
pub fn generate_reject(&mut self, pkt: &[u8]) -> Option<Frame> {
    let mut frame = self.alloc_frame(pkt.len());
    self.write_reject_headers(&mut frame, pkt);
    if !self.acquire_reject_token() {
        return None;
    }
    Some(frame)
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Dataplane receives a packet matching a reject rule.
2. `generate_reject` allocates UMEM memory and writes L2-L4 headers.
3. The rate limiter check fails.
4. The allocated frame is discarded, incurring unnecessary heap/UMEM allocation overhead under load.

- **Irrefutability Proof & Upstream Verification**:
`alloc_frame` is invoked before `acquire_reject_token` is checked, causing wasteful packet assembly under high-rate reject floods.

- **vSRX Parity & Systems Impact**:
- High CPU utilization and UMEM exhaustion under reject packet floods.

- **Suggested Fix Direction & Labels**:
- Evaluate the rate limit token check before allocating any packet buffers or writing headers.
- Labels: performance, reject-handler

---

### AGY-143-03 - Output-Filter Dropped Rejects Counted as Successful Transmissions

- **Severity**: Low
- **Subsystem**: Dataplane Telemetry
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/poll_descriptor/mod.rs:884-898](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L884)

```rust
if let Some(reject_frame) = self.build_reject(pkt) {
        self.stats.reject_sent.inc();
        self.tx_ring.push(reject_frame);
    }
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Reject packet is built and `stats.reject_sent` is incremented.
2. The frame is pushed to the egress path.
3. An egress firewall filter drops the packet.
4. Egress packet counters register the drop, but reject telemetry continues to report the packet as successfully sent.

- **Irrefutability Proof & Upstream Verification**:
The `reject_sent` counter is incremented before the frame is passed through output filter checks and tx ring flush validation.

- **vSRX Parity & Systems Impact**:
- Inaccurate firewall audit logs and telemetry counts.

- **Suggested Fix Direction & Labels**:
- Only increment the reject transmission counter after output filters approve the frame.
- Labels: bug, telemetry, statistics

---

## 5. Suggested Issue Split

1. **Resolution of AGY-143-01**: Implement dynamic bounds check and validation for Single Global Rate-Limit Bucket Starvation Hazard for Local Reject Responses.
2. **Resolution of AGY-143-02**: Implement dynamic bounds check and validation for Reject Reply Packet Allocation Performed Before Evaluating Rate Limiter.
3. **Resolution of AGY-143-03**: Implement dynamic bounds check and validation for Output-Filter Dropped Rejects Counted as Successful Transmissions.

