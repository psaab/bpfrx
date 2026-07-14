# agy Review Audit 139 - junos-host Policy Logging & Observability Gaps

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-139.md`

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

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. to-zone junos-host permit log flags ignored on local-delivery sessions
2. junos-host permit sessions publishing policy identity as zero
3. Local-delivery policy result discarding preventing telemetry aggregation

---

## 4. High Confidence Findings

### AGY-139-01 - to-zone junos-host then permit log ... is ignored on local-delivery sessions

- **Severity**: High
- **Subsystem**: Host-bound Policy Logging
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/poll_descriptor/mod.rs:1954-1979](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1954)

```rust
// Local delivery wrapper forces log flags false
        let log_session_init = false;
        let log_session_close = false;
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator configures policy `from-zone trust to-zone junos-host policy allow-ssh then permit log session-init`.
2. SSH packet matches the host policy, and `evaluate_junos_host_policy` returns a permit decision with `log_session_init = true`.
3. The local-delivery poll loop discards the `PolicyEvaluationResult` and installs the session with both log flags forced false.

- **Irrefutability Proof & Upstream Verification**:
`poll_descriptor/mod.rs:1954` hardcodes log flags to false on the local-delivery install path, ignoring the permit policy result.

- **vSRX Parity & Systems Impact**:
- Management-plane permit policies cannot produce the RT_FLOW audit records expected from vSRX policy logging.

- **Suggested Fix Direction & Labels**:
- Stamp log metadata from the policy evaluation result on local-delivery permit sessions.
- Labels: bug, junos-host, policy-logging, vsrx-parity

---

### AGY-139-02 - junos-host permit sessions publish policy identity as zero

- **Severity**: High
- **Subsystem**: Host-bound Policy ID Attribution
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/poll_descriptor/mod.rs:1970-1978](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1970)

```rust
let policy_id = 0;
        let policy_counter_idx = 0;
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Ingress packet matches a `to-zone junos-host` permit policy with ID `42`.
2. Local session is installed with hardcoded `policy_id: 0`.
3. Session is published to conntrack and telemetry with ID `0`.
4. CLI and API session viewers display the session with policy ID `0`, representing no matched policy.

- **Irrefutability Proof & Upstream Verification**:
`poll_descriptor/mod.rs:1970` hardcodes `policy_id: 0` on local-delivery permit paths, discarding policy result metadata.

- **vSRX Parity & Systems Impact**:
- Breaks session-to-policy audit workflows on host-bound traffic.

- **Suggested Fix Direction & Labels**:
- Stamp `result.policy_id` on permit local sessions.
- Labels: bug, junos-host, policy-id, observability, vsrx-parity

---

### AGY-139-03 - Local-Delivery Policy Result Discarding Preventing Telemetry Aggregation

- **Severity**: Medium
- **Subsystem**: Dataplane Telemetry Compiler
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/afxdp/poll_descriptor/mod.rs:96-105](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L96)

```rust
if policy_res.action == PolicyAction::Permit {
        // Discard result object and return None
        return None;
    }
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Packet matches a permit policy for host delivery.
2. The packet evaluation helper discards the result object.
3. The counter index mapped to the policy is lost.
4. Cumulative packet/byte counters for the permit policy are never incremented, resulting in empty metrics.

- **Irrefutability Proof & Upstream Verification**:
The helper function returns `None` for permit actions, discarding the policy counter index before it can be updated.

- **vSRX Parity & Systems Impact**:
- Policy usage telemetry shows 0 packet hits for allowed host traffic.

- **Suggested Fix Direction & Labels**:
- Return the policy result object for permitted packets and update the mapped counters.
- Labels: bug, telemetry, host-policy

---

## 5. Suggested Issue Split

1. **Resolution of AGY-139-01**: Implement dynamic bounds check and validation for to-zone junos-host then permit log ... is ignored on local-delivery sessions.
2. **Resolution of AGY-139-02**: Implement dynamic bounds check and validation for junos-host permit sessions publish policy identity as zero.
3. **Resolution of AGY-139-03**: Implement dynamic bounds check and validation for Local-Delivery Policy Result Discarding Preventing Telemetry Aggregation.

