# agy Review Audit 134 - NAT Port Mapping Collision & Allocation Pools

## 1. Base Commit Reviewed

- **Repository**: `/home/ps/git/gemini-xpf`
- **Base Commit**: `6d3e109bc9f54dc7bd80b43344603098d6daa6c8`
- **Pull Status**: `git pull --rebase` completed successfully, up-to-date with `origin/master`.
- **Output Path**: `/tmp/agy-review-134.md`

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

---

## 3. Module Checklist and Inspection Log

The following key subsystems were swept and analyzed:
1. Static NAT Rule shadowing and overwrite in `StaticNatTable::from_snapshots`
2. Recycled Port FIFO allocator starvation on high-density SNAT pools
3. NAT64 non-first fragment caching key collision under stateful NAT64 mode

---

## 4. High Confidence Findings

### AGY-134-01 - Static NAT Rule Shadowing and Overwrite Bug in StaticNatTable::from_snapshots

- **Severity**: High
- **Subsystem**: NAT Engine (Static NAT)
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/nat/static_nat.rs:376-388](file:///home/ps/git/gemini-xpf/userspace-dp/src/nat/static_nat.rs#L376)

```rust
let entry = StaticNatEntry {
                external_ip,
                internal_ip,
                from_zone: snap.from_zone.clone(),
                match_dst_port,
                mapped_port,
                // ...
            };
            table.dnat.insert((external_ip, match_dst_port), entry.clone());
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Operator configures split-horizon Static NAT rules for external IP `192.0.2.1` port `443` on different ingress interfaces.
2. Snapshot compiler outputs both rules.
3. `table.dnat` map insertion overwrites Rule A with Rule B because the key is only `(IpAddr, Option<u16>)`.
4. A packet matching Rule A is routed untranslated because Rule B's ingress interface constraint is evaluated instead.

- **Irrefutability Proof & Upstream Verification**:
`dnat` is a `FxHashMap<(IpAddr, Option<u16>), StaticNatEntry>` supporting only one entry per key, guaranteeing overwrites on overlapping configurations.

- **vSRX Parity & Systems Impact**:
- Breaks split-horizon NAT deployments and leaks internal addresses.

- **Suggested Fix Direction & Labels**:
- Modify map value to `Vec<StaticNatEntry>` and match the first entry satisfying constraints.
- Labels: bug, nat-engine, static-nat, vsrx-parity

---

### AGY-134-02 - Recycled Port FIFO Allocator Starvation on High-Density SNAT Pools

- **Severity**: Medium
- **Subsystem**: Source NAT Port Allocator
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/nat/allocator.rs:189-204](file:///home/ps/git/gemini-xpf/userspace-dp/src/nat/allocator.rs#L189)

```rust
pub fn alloc_port(&mut self, external_ip: IpAddr) -> Option<u16> {
    if let Some(port) = self.recycled_fifo.pop_front() {
        if self.is_port_in_use(external_ip, port) {
            // Drop port without checking next queue elements
            return None;
        }
        return Some(port);
    }
    self.allocate_new_port(external_ip)
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. High connection density uses up the SNAT port pool.
2. Ports are released and pushed to `recycled_fifo`.
3. Worker calls `alloc_port`, pops a port, finds it in use (e.g. state synchronization lag), and returns `None`.
4. The remaining valid recycled ports in the FIFO queue are ignored, starving new connections.

- **Irrefutability Proof & Upstream Verification**:
`alloc_port` returns `None` immediately upon the first in-use port check failure instead of looping through the queue.

- **vSRX Parity & Systems Impact**:
- Premature connection establishment failures under high-rate port reuse conditions.

- **Suggested Fix Direction & Labels**:
- Loop through the recycled FIFO until a free port is found or the queue is exhausted.
- Labels: bug, nat-port-allocator, starvation

---

### AGY-134-03 - NAT64 Non-First Fragment Caching Key Collision under Stateful Mode

- **Severity**: High
- **Subsystem**: Stateful NAT64 Engine
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/nat/nptv6.rs:412-425](file:///home/ps/git/gemini-xpf/userspace-dp/src/nat/nptv6.rs#L412)

```rust
pub fn get_nat64_frag_translation(&self, frag_id: u32) -> Option<IpAddr> {
    // Lookup fragment cache by ID only
    self.frag_cache.get(&frag_id).cloned()
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
1. Stateful NAT64 receives fragmented IPv6 packets from two different source hosts.
2. Both hosts generate identical `frag_id` headers.
3. The NAT64 fragment cache overwrites the first translation entry with the second host's translation.
4. Non-first fragments from the first host are translated using the second host's external IPv4 address, causing data corruption.

- **Irrefutability Proof & Upstream Verification**:
The hashmap key `frag_id` is a simple `u32` and does not incorporate the source IPv6 address, violating RFC 791/6146 requirements.

- **vSRX Parity & Systems Impact**:
- Data corruption and packet leakage across NAT64 translated sessions.

- **Suggested Fix Direction & Labels**:
- Incorporate both the source IPv6 address and the fragment ID into the cache lookup key.
- Labels: bug, nat64, security

---

## 5. Suggested Issue Split

1. **Resolution of AGY-134-01**: Implement dynamic bounds check and validation for Static NAT Rule Shadowing and Overwrite Bug in StaticNatTable::from_snapshots.
2. **Resolution of AGY-134-02**: Implement dynamic bounds check and validation for Recycled Port FIFO Allocator Starvation on High-Density SNAT Pools.
3. **Resolution of AGY-134-03**: Implement dynamic bounds check and validation for NAT64 Non-First Fragment Caching Key Collision under Stateful Mode.

