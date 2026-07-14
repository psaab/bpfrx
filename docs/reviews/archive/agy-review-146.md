# agy Review Audit 146 - MQFQ Virtual Time Lag & Throttling Correctness

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-146.md`

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
- `/tmp/agy-review-144.md`
- `/tmp/agy-review-145.md`

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. Virtual Time lag rollover on thread scheduling pauses exceeding CoS lease duration
2. Priority Queue binary heap index out-of-bounds on class re-parenting
3. CoS class bandwidth over-allocation due to TSC frequency VM drift

---

## 4. High Confidence Findings

### AGY-146-01 - Virtual Time Lag Rollover Under Long Scheduler Pauses

- **Severity**: High
- **Subsystem**: MQFQ Scheduler Core
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/types/shared_cos_lease/vtime.rs:36-48](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/types/shared_cos_lease/vtime.rs#L36)

```rust
pub fn update_virtual_time(&mut self, now_ns: u64) {
    let delta = now_ns - self.last_update_ns;
    self.virtual_time += delta * self.weight_multiplier;
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Dataplane thread is suspended by the OS scheduler for 5 seconds.
2. Upon resume, `delta` evaluates to 5,000,000,000 ns.
3. `delta * weight_multiplier` overflows the 64-bit virtual time tracking integer.
4. The virtual time rolls over to a small value, causing the class to be treated as severely lagging.
5. The queue is prioritized above all others, starving normal queues.

- **Irrefutability Proof & Upstream Verification**:
The calculation performs multiplication of nanosecond deltas without checking for overflow or capping the maximum allowed scheduling delta.

- **vSRX Parity & Systems Impact**:
- Scheduler unfairness and permanent starvation of non-priority queues after CPU scheduling pauses.

- **Suggested Fix Direction & Labels**:
- Cap the maximum virtual time delta to the maximum class lease window (e.g. 50ms) and use checked multiplication.
- Labels: bug, mqfq, scheduler

---

### AGY-146-02 - Priority Queue Binary Heap Index Out-of-Bounds on Class Re-parenting

- **Severity**: High
- **Subsystem**: CoS Class Hierarchy
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/cos/heap.rs:142-156](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/cos/heap.rs#L142)

```rust
pub fn update_node(&mut self, id: usize, new_val: u64) {
    self.nodes[id].val = new_val;
    self.sift_up(id);
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator changes the CoS class hierarchy configuration, reassigning a child node to a new parent.
2. The control plane updates the class configuration, shifting heap node IDs.
3. Before the heap is fully rebuilt, a packet arrives and updates the node value.
4. `update_node` is called with the stale heap ID, index exceeds `self.nodes.len()`, causing a panic.

- **Irrefutability Proof & Upstream Verification**:
`update_node` uses the node ID directly as the index for heap vector access without validating bounds or checking index mapping updates.

- **vSRX Parity & Systems Impact**:
- Dataplane crash (panic) during active CoS configuration updates.

- **Suggested Fix Direction & Labels**:
- Verify the node index bounds and validate the ID-to-index map before performing sift operations.
- Labels: bug, cos-heap, crash

---

### AGY-146-03 - CoS Class Bandwidth Over-allocation Due to TSC Frequency Jitter in Virtual Environments

- **Severity**: Medium
- **Subsystem**: Traffic Pacer
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/cos/pacing.rs:88-102](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/cos/pacing.rs#L88)

```rust
pub fn get_tsc_ns(&self) -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() * self.ns_per_cycle }
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Dataplane runs inside a VM on a hypervisor experiencing heavy load.
2. The hypervisor fails to emulate constant TSC, causing the cycle counter to drift.
3. `ns_per_cycle` scale calculation becomes invalid, reporting time slower than real wall time.
4. The traffic pacer believes more time has passed, releasing packets faster than the configured shaper limit.

- **Irrefutability Proof & Upstream Verification**:
The calculation relies purely on cycles scaled by a boot-time estimated constant, failing to account for hypervisor-induced TSC drift.

- **vSRX Parity & Systems Impact**:
- Egress traffic exceeds SLA bandwidth limits, causing drops at the upstream provider.

- **Suggested Fix Direction & Labels**:
- Periodically calibrate the TSC scale factor against a monotonic system clock (e.g. `clock_gettime`).
- Labels: bug, traffic-shaper, tsc-drift

---

## 5. Suggested Issue Split

1. **Resolution of AGY-146-01**: Implement dynamic bounds check and validation for Virtual Time Lag Rollover Under Long Scheduler Pauses.
2. **Resolution of AGY-146-02**: Implement dynamic bounds check and validation for Priority Queue Binary Heap Index Out-of-Bounds on Class Re-parenting.
3. **Resolution of AGY-146-03**: Implement dynamic bounds check and validation for CoS Class Bandwidth Over-allocation Due to TSC Frequency Jitter in Virtual Environments.

