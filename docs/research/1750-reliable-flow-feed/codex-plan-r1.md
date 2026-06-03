# Codex hostile plan review — #1750 r1

Session id: 019e8aff-29b9-7e03-bc41-8c8e535966c7 (gpt-5.5, read-only sandbox).

## VERDICT: PLAN-NEEDS-MAJOR

The flow-cache scan is a valid source, but the plan's "atomic publish" wording
is false at the exposed binding API. More importantly, the #1748 controller
appears to compare slot-derived worker rates against row-derived worker IDs, a
quoted-line defect that can independently produce `candidate_count=0` and zero
installs even with perfect flow rows. Path 1 must include fixing that
identifier mismatch, otherwise the recommended path is not the cheapest correct
one and may remain live-inert.

## Findings (verbatim summary)
1. Same-scan claim TRUE; atomic-publish claim FALSE. `active_flow_debug_entries`
   increments count and pushes rows in one loop (`flow_cache.rs:478-493`), but
   publication is two separate objects: `active_flow_count.store(..Relaxed)`
   (`debug_state.rs:217-224`) and a separate `publish_flow_worker_map` ArcSwap
   store; `FlowWorkerMapSnapshot` (`umem/mod.rs:250-255`) carries only
   rows/truncation. A reader can observe new count with old rows.
2. Stronger live zero-install defect: slot/worker_id mismatch. `workers.live`
   keyed by binding `slot` (`worker_manager.rs:5-8`, `bringup.rs:46-55`); but
   `tick_rebalance` treats the map key as `worker_id`
   (`coordinator/rebalance.rs:209-228`); rows publish the real `worker_id`
   (`debug_state.rs:229-232`); `select_move` filters
   `f.worker_id == hottest.worker_id` (`controller.rs:507-511`). Can make
   `candidate_count == 0` with a correct non-empty row list. Path 1/2 do not fix
   it.
3. Rows-empty/count-positive within one scan ≤256 is impossible (shared
   `active_entry_age`, truncation only after `rows.len() >= limit`,
   `last_used_epoch==0` invisible to both) — so the symptom is consumer/publish
   skew or controller filter loss (`rebalance.rs:249-263`).
4. Q2 conditionally sound: code uses row-derived `candidate_count`
   (`controller.rs:514,529-530`), not `active_flow_count`; if rows are
   filtered/stale/worker-id-corrupted the fallback may never engage.
5. §6.3 carry-forward cold-path & non-double-counting for same-key overwrite,
   but does not cover lookup-driven stale eviction (lookup clears before insert,
   `flow_cache.rs:625-652`) nor LRU eviction (`:705-710`) without a side table.
