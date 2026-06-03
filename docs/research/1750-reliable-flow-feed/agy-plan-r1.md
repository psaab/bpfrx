# AGY adversarial plan review — #1750 r1

Job: adversarial-review-mpxd0g51-y35972 (read-only).

## Implicit verdict: PLAN-NEEDS-MAJOR (atomic-publish claim FALSE; §6.3 dead code) — PLAN-KILL rightly dismissed.

## Findings (verbatim summary)
1. **Same-scan/atomic-publish claim is FALSE.** Count and rows are one scan
   (`active_flow_debug_entries`, flow_cache.rs:465-519) but NOT published
   atomically: `active_flow_count.store(..Relaxed)` (debug_state.rs:223-224) is
   a separate atomic from `publish_flow_worker_map` →
   `flow_worker_map.store(Arc::new(FlowWorkerMapSnapshot{rows,truncated}))`
   (umem/mod.rs:817-824). `BindingLiveSnapshot` (worker/mod.rs:1137-1175) does
   not even encapsulate the rows; coordinator loads count via
   `snapshot().active_flow_count` and rows separately via `flow_worker_map()`
   (status.rs:168-188) → direct cross-snapshot timing skew.
2. **Rows-empty/count-positive WITHOUT a consumer bug is possible** via: (a)
   decoupled scraping/cross-snapshot skew; (b) idle publish lag — the 0xFFFF
   (65,536) poll-iteration gate means a low-PPS sleeping worker can take
   ~655 s at 100 PPS to publish; (c) age-out timing — `active_entry_age`
   active window is <10 epochs (~650 ms), so a ~1 pkt/sec flow ages out between
   packets and drops from BOTH count and rows ~350 ms of every second.
3. **Q2 sound:** homogeneous traffic → per-flow rate ≈ `W.byte_rate /
   W.active_flow_count`; fallback estimate physically correct; R1 round-robin
   re-pin validates. Fine-grained rates not needed for homogeneous balancing.
4. **§6.3 carry-forward is mathematically correct but DEAD CODE in production.**
   The dedup-on-insert branch (flow_cache.rs:686-694) never executes: hot path
   always `lookup_counted` first (poll_descriptor/mod.rs:1945); a hit skips
   insert; a miss means the key is absent or was just deleted in
   `lookup_counted` (lines 628/638/648) on generation/epoch mismatch — so insert
   never finds a matching key to dedup. The proposed fix fails to prevent rate
   resets under LRU eviction churn (LRU displacement overwrites slots with other
   keys).
5. **PLAN-KILL rightly dismissed.** Path 1 — extend `FlowWorkerMapSnapshot` to
   bundle `active_flow_count` and publish both from the scan tuple in the SAME
   ArcSwap store — cleanly solves the cross-snapshot skew with no hot-path cost.
