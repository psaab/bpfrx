# agy Review Audit 138 - Security Zone Invariants & Tolerant Snapshot Loading

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-138.md`

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

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. Tolerant nil zone snapshots host-inbound admit-all fallback
2. Zone ID shifting/mismatch across HA peers due to nil zone inclusion
3. Intrazone default-permit logging policy logging metadata mismatch

---

## 4. High Confidence Findings

### AGY-138-01 - Tolerant nil zone snapshots can make a configured zone host-inbound admit-all

- **Severity**: High
- **Subsystem**: Host-inbound Snapshot Generation
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/dataplane/userspace/zones.go:419-432](file:///home/ps/git/gemini-xpf/pkg/dataplane/userspace/zones.go#L419)

```rust
for name, cfg := range zones {
		snap := ZoneSnapshot{
			Name: name,
			HostInboundConfigured: cfg != nil,
		}
		// ...
	}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Lenient config sync carries `Security.Zones["trust"] = nil`.
2. Snapshot allocates a valid zone ID for `trust`, but leaves `HostInboundConfigured = false`.
3. Rust zones map receives `trust` zone ID, but host-inbound entry is skipped in `zones.rs`.
4. Ingress packet from `trust` queries host-inbound map. Finding no entry, the check falls back to `None => true` (admit all).

- **Irrefutability Proof & Upstream Verification**:
`host_inbound.rs:479` returns `true` when no zone entry exists in the map. Tolerant/nil zones create mapped zone IDs without map entries, triggering this fallback.

- **vSRX Parity & Systems Impact**:
- Nil-zone configurations on lenient load bypass host-inbound admission filters entirely.

- **Suggested Fix Direction & Labels**:
- Skip nil zones during snapshot generation or compile them with empty token sets.
- Labels: bug, host-inbound, ha-sync, security

---

### AGY-138-02 - Zone ID Shifting across HA Peers due to nil Zone Inclusion

- **Severity**: Medium
- **Subsystem**: Zone Snapshot Allocation
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/dataplane/userspace/zones.go:413-421](file:///home/ps/git/gemini-xpf/pkg/dataplane/userspace/zones.go#L413)

```rust
for i, name := range sortedZoneNames {
		zones[name].ID = uint16(i + 1)
	}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Peer A has configured `{"dmz": nil, "trust": {...}}`.
2. Peer B has configured `{"trust": {...}}`.
3. Peer A assigns `trust` ID 2; Peer B assigns `trust` ID 1.
4. HA session sync messages transmit session logs using numeric zone IDs. The mismatch causes Peer B to associate trust sessions with untrusted zones, leading to incorrect policy drops.

- **Irrefutability Proof & Upstream Verification**:
Zone ID assignment iterates over sorted configured names, including nil zones, causing numbering divergence if configuration shapes differ between peers.

- **vSRX Parity & Systems Impact**:
- HA session synchronization mismatches and incorrect security policies applied post-failover.

- **Suggested Fix Direction & Labels**:
- Filter out nil zone entries before assigning numeric IDs.
- Labels: bug, ha-sync, zone-id

---

### AGY-138-03 - Intrazone Default-Permit Policy Logging Option Mismatch

- **Severity**: Medium
- **Subsystem**: Default Policy Resolver
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/policy.rs:2838-2849](file:///home/ps/git/gemini-xpf/userspace-dp/src/policy.rs#L2838)

```rust
pub fn resolve_default_action(&self, src_zone: &str, dst_zone: &str) -> PolicyAction {
    if src_zone == dst_zone {
        return PolicyAction::Permit; // Intrazone default permit
    }
    PolicyAction::Deny
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator configures `default-policy-log [ session-init ]`.
2. Traffic flows between interfaces inside the same zone (`trust` -> `trust`).
3. The default action permits traffic, but `resolve_default_action` does not stamp default policy logging metadata onto the session.
4. Intrazone default permit traffic escapes audit log generation.

- **Irrefutability Proof & Upstream Verification**:
The intrazone permit logic returns `PolicyAction::Permit` early without applying the default policy logging configurations.

- **vSRX Parity & Systems Impact**:
- Loss of audit logs for allowed intrazone traffic.

- **Suggested Fix Direction & Labels**:
- Apply configured default logging flags to all intrazone permit actions.
- Labels: bug, policy, logging

---

## 5. Suggested Issue Split

1. **Resolution of AGY-138-01**: Implement dynamic bounds check and validation for Tolerant nil zone snapshots can make a configured zone host-inbound admit-all.
2. **Resolution of AGY-138-02**: Implement dynamic bounds check and validation for Zone ID Shifting across HA Peers due to nil Zone Inclusion.
3. **Resolution of AGY-138-03**: Implement dynamic bounds check and validation for Intrazone Default-Permit Policy Logging Option Mismatch.

