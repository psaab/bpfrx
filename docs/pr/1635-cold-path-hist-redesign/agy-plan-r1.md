An adversarial plan review has been conducted for the proposed redesign of the **xpf cold-path histogram primitive + per-zone-pair slot map** (xpf issue #1635, Plan v2, commit `913ab5f20`). 

As an expert in HPC networking, OS, data structures, CPU design, and networking protocols, I have hostile-verified this architecture. The findings reveal critical structural risks, math errors in cardinality, and a severe hot-path performance bottleneck in the plan.

Below is the detailed review and final verdict.

---

# Final Verdict: PLAN-NEEDS-MINOR

The core of the Plan v2 is **conceptually solid** and solves the structural defects of v1 (5x quantile error, birthday-paradox hash collisions, and packet-mix-ratio aggregate corruption). However, the plan cannot be marked **PLAN-READY** as-is. It contains a massive cardinality calculation error, a hot-path performance hazard, and a lifetime overflow vulnerability. These must be addressed before implementation begins.

---

## 1. Deep Dive Hostile Verification of Specific Choices

### 1.1 Bucket Layout & Prometheus Cardinality Budget (F5 Math Error Escalation)
* **Cardinality Math Error**: The plan (§2.4) states: 
  > *"Cardinality budget: 128 slots × ~8 workers × 8 metric families ≈ ~8K series per scrape worst case. Prometheus handles this trivially."*
  This is a **critical math error**. In Prometheus, a histogram metric family is not a single series; it generates a separate series for *each bucket* (labeled by `le`).
  * Under Plan v2, the `ns_bucket_v2` metric generates: `128 slots × 8 workers × 80 buckets = 81,920` time-series.
  * Adding the other 3 per-slot metrics (`samples`, `sum_ns`, `alias_seen`) adds: `128 slots × 8 workers × 3 metrics = 3,072` series.
  * For **12 workers** (the largest deployment seen), the total is: `128 × 12 × (80 + 3) = 106,240` time-series.
  * Scraped at `1 scrape/sec` sustained, generating >100K active series for a single diagnostic metric per node creates high risk of Prometheus scrape timeouts, massive storage overhead, and dashboard rendering failures.
* **Stride & Pivot Point Recommendation**: Pivoting the linear-to-exponential band at **512 ns** instead of 1024 ns is a superior design.
  * **Linear Band**: `[0, 512) ns` split into 32 buckets of 16-ns stride. (32 buckets).
  * **Exponential Band**: `[512, 2^24) ns` split into 15 power-of-two buckets (`[512, 1024)`, `[1024, 2048)`, ..., `[2^23, 2^24)`). (15 buckets).
  * **Saturate Band**: `ns ≥ 2^24` (1 bucket).
  * **Total Buckets = 48** (down from 80).
  * **Relative Error Verification**: A sample at 600 ns landing in the `[512, 1024)` bucket has a worst-case error of `(1024-512)/768 = 67%` (1.67× error), which easily satisfies the "≤2× error" target. 
  * **Impact**: Halving the bucket count from 80 to 48 reduces Prometheus metric cardinality by **40%** and speeds up `histogram_quantile()` computation significantly, with zero loss in resolution in the critical `50-150 ns` range.

### 1.2 Slot Count & gRPC / Wire Footprint
* ** Dynamic Policies & Lifetime Overflow**: The plan allocates a static `128` slots in the Rust worker arrays and handles overflow by dropping any 129th pair. It assumes 128 is "10x headroom".
  * In virtualized or Kubernetes environments, Network Policies and Zone Pairs are highly dynamic. Zones are created/destroyed as namespaces or tenants scale.
  * If a long-running daemon sees 128 distinct pairs *over its lifetime*, it will hit the overflow threshold and permanently freeze/drop metrics for all new zone-pairs, requiring a manual `systemctl restart xpfd`. This is a severe operational hazard.
* **The Sparse Serialization Solution (Critical Upgrade)**: 
  Instead of serializing the full 128-element arrays (which sends 116 slots of useless zeros over the wire in a 12-pair cluster), the Rust coordinator status path should only serialize **active slots** (slots currently assigned to active zone-pairs).
  * The wire structures (`cold_path_hist`, `cold_path_sum_ns`, etc.) will only contain elements for active slots (e.g., length 12).
  * The Go collector will dynamically loop over `len(w.ColdPathHist)` and map them to their corresponding `from_zone` and `to_zone` strings.
  * **Operational Impact**: With sparse serialization, wire footprint drops from 82 KB/worker to **~8 KB/worker** (a 90% bandwidth reduction!). More importantly, we can safely increase the maximum Rust slot map capacity to **256 or 512** with *zero* wire overhead, completely eliminating the lifetime overflow risk.

### 1.3 Stable Slot Assignment & HA Failover
* **Failover Safety**: Verified. Because the Prometheus scraper and the Scale Target table correlate metrics strictly via string labels (`from_zone` / `to_zone`) rather than numeric slot indices, any mismatch of slot mappings between HA peers (e.g., `fw0` using slot 3, `fw1` using slot 5 for the same pair) is harmless.
* **Inconsistency in §2.3 Step 3**: The example states that D (new pair replacing B) gets slot 3, leaving B's slot 1 vacant but unused. Yet the prose says "append-only with hole reuse." 
  * *Resolution*: The implementation must follow **immediate slot reuse with cleanup**. When B is removed and D is added, slot 1 should be reassigned to D, but the control plane must explicitly reset/zero slot 1's atomic counters in all workers. This prevents stale B history from leaking into D's initial metrics.

### 1.4 Wire-Protocol Version Tagging
* **Upgrade Safety**: Verified. The `cold_path_layout_version = 2` u32 tag safely prevents older Go control planes from misinterpreting the new 80-bucket (or 48-bucket) arrays as v1.
* **Rolling Upgrades**: During rolling upgrades, the central Prometheus instance will see both `_v2` and `_v1` metrics. This is safe; dashboards should explicitly transition to querying `_v2` metrics once all nodes are upgraded.

### 1.5 Public API Preservation
* **API Breakage**: Verified. Grep searches of the codebase confirm that `zone_pair_slot` and `record_sample` are only consumed within `cold_path_hist.rs` and the hot-path `poll_descriptor/mod.rs`. Removing `zone_pair_slot` and shifting `record_sample` to take pre-computed slot IDs will not break any external Rust dependencies or benchmarks (only internal unit tests, which will be updated).

### 1.6 Hidden Invariants
* **alias_seen Repurposing**: In Plan v2, `alias_seen` transitions from a publication filter to a hard-error invariant (it should always be 0 because the direct map is 1-to-1). This is correct and serves as an excellent control-plane diagnostic. 
  * *Recommendation*: The Rust field should be documented clearly as `builder_collision_detected` to avoid confusion with the old hashing terminology.

### 1.7 Performance Pressure Test: Hot-Path Bottleneck (Critical Risk)
* **The Issue**: Plan §4.4 proposes that on every sampled packet, the hot path runs:
  ```rust
  let Some(slot) = crate::afxdp::cold_path_hist::lookup_slot(
      &worker_ctx.forwarding.cold_path_slot_map, from_zone_id, to_zone_id
  ) else { ... };
  ```
  This is a **critical performance risk**. `lookup_slot` performs a `FastMap` (hashmap) lookup *on the hot path*. Under standard 1-in-256 sampling, this cost is amortized. 
  * However, when the operator enables **1-in-1 sampling** (a standard debugging mode for low-traffic lines), the hot path will execute a hashmap lookup on *every single packet*. At 10 Mpps, this 5–10 ns overhead consumes **5% to 10% of the entire packet processing time budget** (which is ~100 ns total). This is a severe regression.
* **Remediation**: Precompute the `slot_idx: Option<u8>` directly inside the `Binding` struct during config-apply time. Because a binding's `from_zone_id` and `to_zone_id` are static for its lifetime, the hot-path record site can simply retrieve `binding.cold_path_slot` via a single, direct pointer dereference:
  ```rust
  if let Some(slot) = binding.cold_path_slot {
      binding.cold_path.record_sample(slot, delta_ns);
  }
  ```
  This completely bypasses the `FastMap` lookup on the hot path.

### 1.8 Architectural Angle from #1622
* **Aggregate vs. Per-Zone-Pair**: Committing strictly to per-zone-pair publication and removing the mixed "aggregate row" in the dataplane is architecturally correct. Pre-aggregating in the dataplane corrupts the distribution. Operators should perform aggregate calculations (e.g., p50 across all zone pairs) in PromQL by summing cumulative buckets.

### 1.9 Slot-Map Overflow Handling
* **Hard-Refuse Verdict**: Hard-refuse is acceptable only if the slot capacity is sufficiently high (e.g., 256 or 512). If slot count is capped at 128 without slot reuse, dynamic policies will inevitably trigger permanent metrics blackout for new zones over a long daemon uptime.
  * Implementing **Sparse Serialization** (discussed in 1.2) unlocks a larger slot limit (256/512) with zero wire penalty.

---

## 2. Actionable Remediation Checklist for Plan v3

To progress to `PLAN-READY`, the plan must be revised to incorporate the following modifications:

- [ ] **1. Halve bucket count via 512 ns Pivot**: Re-span the layout to 48 buckets total: 32 linear buckets of 16-ns stride (`[0, 512) ns`) and 15 exponential power-of-two buckets (`[512, 2^24) ns`), plus 1 saturate bucket.
- [ ] **2. Shift lookup to Control Plane**: Add `cold_path_slot: Option<u8>` to the `Binding` struct. Populate it during config-apply in `forwarding_build/mod.rs` and read it directly on the hot path in `poll_descriptor/mod.rs` to eliminate the hot-path hashmap lookup.
- [ ] **3. Implement Sparse Wire Serialization**: Update the Rust `coordinator/status.rs` and Go wire protocol to only serialize and transmit arrays for *active* slots. 
- [ ] **4. Expand Slot Capacity**: Increase `POLICY_COLD_PATH_ZONE_PAIR_SLOTS` from 128 to **256** (or 512) to provide massive dynamic policy headroom.
- [ ] **5. Immediate Slot Reuse with Cleanups**: Allow slots of deleted zone-pairs to be immediately reused by new pairs, but enforce that the control plane zeroes the slot's atomic accumulators upon reassignment.
- [ ] **6. Document internal invariants**: Document `alias_seen` in Rust as a builder collision diagnostic, and update the Go-side cardinality estimates to reflect the corrected bucket multiplier.
