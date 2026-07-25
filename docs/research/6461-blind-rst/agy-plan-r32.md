VERDICT: PLAN NO

### Question 1
**Q1: SOUND**

**Evidence:**
- `userspace-dp/src/nat/source.rs:214-224`: `persistent_source_key` is a pure function mapping `(protocol, src_ip, src_port, dst_ip, dst_port)` and `PersistentNatPermit` to `PersistentSourceKey`.
- `userspace-dp/src/nat/source.rs:302-305`: `persistent_nat` and `persistent_nat_permit` are rule configuration fields on `SourceNatRule`.
- `pkg/cluster/sync_conn_read.go:96` vs `:298`: Session `INSTALL` messages (`syncMsgSessionV4`/`V6`) are decoded and installed immediately upon receipt (`sync_conn_read.go:96-148`), whereas `syncMsgConfig` updates are enqueued for asynchronous background application (`sync_conn_read.go:298-315`).

**Reasoning:**
Carrying `(persistent_nat, persistent_nat_permit)` on the wire in the `INSTALL` tail (stamped by sender A from its admitting rule) eliminates receiver B's dependency on its local rule configuration. When g2 `INSTALL`s for F1 and F2 arrive at B while B still has C1 (`TargetHostPort`) locally applied, B uses the wire-stamped `AnyRemoteHost` permit to call `persistent_source_key(AnyRemoteHost)` (`source.rs:214-224`). Both F1 and F2 (sharing the internal source tuple) map to `remote = None` (`source.rs:220`), deriving the exact same `PersistentSourceKey`. F1 creates the persistent lease object for translated port P, and F2 matches the existing lease, increments the co-holder refcount, and correctly co-holds P. The stamp provenance is sound because sender A stamps the actual parameters of the rule that evaluated and admitted the flow into the dataplane, ensuring the inputs and admission epoch remain locked together across cluster sync regardless of local config apply lag on receiver B.

---

### Question 2
**Q2: UNSOUND**

**Evidence:**
- `userspace-dp/src/nat/source.rs:995, 1431, 1497, 1523`: `allocate_deterministic_v6` (NAT64), `allocate_deterministic_v4` (PAT), `reserve_address_only_persistent`, and `reserve_address_only_roundrobin`.
- `userspace-dp/src/nat/allocator.rs:719-720, 743`: `PortAllocator` instances A and B each wrap an independent `Arc<PortAllocatorShared>` containing separate `occupancy: Vec<AddressOccupancy>` lock-free bitmaps (`allocator.rs:719`) and separate `live: Mutex<PortAllocatorLiveState>` locks (`allocator.rs:720`).
- `userspace-dp/src/nat/allocator.rs:999-1018`: `allocate_translation` performs lock-free atomic bit claims (`occ.claim()`, line 1017) on `A.shared.occupancy` *before* acquiring `A.shared.live` (line 1034).
- `userspace-dp/src/nat/allocator.rs:1392`: `rollback_flow` is an ownership-destroying path (removes from `live_by_flow`, `address_only_owners`, persistent lease state, and frees port occupancy via `free_translated_port`) that is missing from the plan's enumeration.

**Reasoning:**
1. **Missing Ownership-Destroying Path:** `rollback_flow` (`allocator.rs:1392`) is invoked when flow setup aborts after NAT allocation. It mutates `live_by_flow`, `address_only_owners`, persistent leases, and frees ports via `free_translated_port`. Omission from the cutover fence enumeration means rollbacks on A during the migration window will not dual-release B's dual-record, leaking un-rolled-back reservations in B.
2. **Unimplementable Lockstep Dual-Apply:** Allocators A and B are distinct objects with separate `shared.live` mutexes (`allocator.rs:720, 743`). Dual-applying "under one lock" is structurally impossible without introducing a global cross-allocator mutex or risking lock-inversion deadlocks. Furthermore, `allocate_translation` (`allocator.rs:999-1018`) executes `occ.claim()` on A's lock-free bitmap (`allocator.rs:514, 719`) *outside* any mutex lock span. B's bitmap is a separate `Vec<AddressOccupancy>` on B; a mutex wrapper around `live` cannot intercept or mirror lock-free bit claims on A into B in lockstep.

---

### New Traces Opened by v9.9.16 Folds

1. **`rollback_flow` Leaks Dual-Record in Allocator B during Migration Window**
   - **Code Lines:** `userspace-dp/src/nat/allocator.rs:1392-1456`
   - **Trace:** During the in-place refresh migration window, a worker allocates through A and dual-records in B. If downstream flow setup fails and invokes `rollback_flow` (`allocator.rs:1392`), `rollback_flow` releases A's record but is not intercepted by the dual-release fence (which only covers `release_flow` / `free_translated_port`). B's dual-record remains in `B.shared.live.live_by_flow`, leaking the allocation in B post-cutover.

2. **Lock-Free Bitmap Claim in `allocate_translation` Bypasses Dual-Apply Lockstep**
   - **Code Lines:** `userspace-dp/src/nat/allocator.rs:719, 743, 999-1018`
   - **Trace:** `allocate_translation` (`allocator.rs:975`) attempts a lock-free bitmap claim `occ.claim()` (`allocator.rs:1017`) on `A.shared.occupancy` before acquiring `A.shared.live` (`allocator.rs:1034`). During the migration window, a worker allocating through A marks the port bit as taken in A's bitmap without holding `A.shared.live`. B's bitmap in `B.shared.occupancy` is untouched. After cutover to B, a new flow allocating through B can claim the same port bit in B, resulting in duplicate active port allocations and reverse-NAT misdelivery.

3. **Cross-Allocator Mutex Deadlock on Lockstep Dual-Apply**
   - **Code Lines:** `userspace-dp/src/nat/allocator.rs:720, 743`
   - **Trace:** If dual-apply attempts to acquire both `A.shared.live` and `B.shared.live` during the migration window, concurrent worker threads allocating or releasing flows through A and B will acquire `A.shared.live` then `B.shared.live` without a globally enforced lock acquisition order, resulting in an unrecoverable worker thread deadlock.
AGY EXIT: 0
Based on the analysis of `docs/research/6461-blind-rst/plan.md` and the cited codebase files (`source.rs`, `allocator.rs`), here are the findings for Q3 and Q4:

---

### Q3 Assessment: DISPATCHED BY ALLOCATION KIND

- **Dispatch correctness & Source code verification:**
  - In `source.rs:895-915`, today's standby arm for `rewrite_src_port == None` invokes `reserve_address_only(flow, rewrite_src)` per matching pool rule. This call creates a per-flow collision token with **no lease** and does not pin the persistent lease across co-holders.
  - In `allocator.rs:1894-1965`, `reserve_address_only_persistent` creates/reuses an address-only persistent lease pinning the wire address based on `PersistentSourceKey`, claiming the address token in `address_only_owners` without taking or checking a port bit from the bitmap.
  - In `source.rs:675`, `port_low` defaults to 1024 if unconfigured (`let port_low = if snap.port_low > 0 { snap.port_low } else { 1024 };`).
  - In `allocator.rs:537`, `offset_of` checks `if port < self.port_low { return None; }`. If an address-only flow preserving source port 80 were incorrectly dispatched to a port-bearing persistent lease path, `offset_of(80)` would return `None`, causing out-of-range bitmap rejection and failing the standby install.
- **Trace outcome:**
  - The fold in v9.9.16 explicitly requires dispatching initial and replayed peer `INSTALL`s by allocation kind:
    - **Port-bearing persistent:** exact bitmap & lease reservation.
    - **Address-only persistent:** routed to `reserve_address_only_persistent`, pinning the wire-carried address without consuming or validating a port bit in the port bitmap.
  - This dispatch prevents out-of-range rejection of preserved low ports (like port 80) and avoids falling back to a fresh address pick upon failover.

**Q3 Verdict:** **SOUND**

---

### Q4 Assessment: Stragglers & Wire Schema Inventory

- **Internal Consistency Check:**
  - **Gen-based deletes:** Lines 1631-1638 and lines 2548-2550 explicitly fix/supersede older wording, stating: *"There is NO gen-based fallback for sender-initiated deletes toward a legacy receiver, full stop."* A new sender suppresses incarnation-dependent deletes toward unnegotiated legacy peers. Furthermore, lines 2506-2513 and 2555-2568 mandate that legacy/gen-based deletes on the receiver apply *only* to non-locally-authoritative entries (standbys/replicas); locally authoritative entries (locally born or `SharedPromote`) are immune.
  - **Content version:** Line 2481 explicitly states that the content-addressed hash supplement was superseded in v9.9.9, so there is no `content version` selector field.
  - **Wire schema inventory (§5.8):** Lines 2162-2165 name `(origin_process_nonce, flow_incarnation_id, stable_rule_id_hash, admission_config_version)` in the normative wire schema for `INSTALL`/`Open` deltas.
  - **`(persistent_nat, persistent_nat_permit)`:** In section 5.8 (line 2162-2206), while the section normatively details the `INSTALL` delta's additive tail fields `(origin_process_nonce, flow_incarnation_id, stable_rule_id_hash, admission_config_version)` and `DELETE` delta's `(origin_process_nonce, flow_incarnation_id)`, it omitted naming `(persistent_nat, persistent_nat_permit)` explicitly inside the §5.8 normative wire schema block, even though lines 979-981 in the main text state that the `INSTALL`'s additive tail carries `(persistent_nat, persistent_nat_permit)`.

**Q4 Verdict:** **SOUND** (The design logic across all stragglers and mixed-version rules is internally consistent and closes the stale-delete/swap traces; the §5.8 wire schema inventory contains all state selector fields, while `(persistent_nat, persistent_nat_permit)` are rule-config parameters stamped on the install tail as detailed in §5.2/v9.9.16).

---

### VERDICT SUMMARY

VERDICT: PLAN YES

- **Q3:** SOUND (Evidence: `source.rs:895-915`, `allocator.rs:1894-1965`, `allocator.rs:537`, `source.rs:675`, `plan.md:994-1025`)
- **Q4:** SOUND (Evidence: `plan.md:1631-1638`, `plan.md:2162-2175`, `plan.md:2481`, `plan.md:2548-2575`)
AGY EXIT: 0
