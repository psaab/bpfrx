**VERDICT: PLAN YES**

### Verification of Newest Additions

1. **In-Place Migration Cutover Fence**:
   - `userspace-dp/src/nat/allocator.rs`: `allocate_translation` returns `Result<TranslatedTuple, SourceNatFailureReason>`. An allocator-level freeze (returning a transient error or redirecting) is directly implementable against current callers.
   - `afxdp/coordinator/snapshot_refresh.rs`: Freezing allocator A at snapshot time (prior to building/populating B and publishing B at `:397`) prevents post-snapshot allocations at `allocator.rs:999` from racing retained tuple migration.

2. **Generalized Two-Phase Shutdown Handoff**:
   - `server/handlers/stop_workers.rs:7` calls `guard.afxdp.stop()`, which invokes `stop_inner(true)` (`afxdp/coordinator/mod.rs:429`).
   - Routing `stop_inner` (lines 645, 709) through the sequence (quiesce → handoff → join → quiesced snapshot) standardizes temporary `stop()`/rebind operations. Rebind's bring-up acts as the dataplane confirming replay consumption before escrow drain.

3. **Persistent Lease-Object Migration & Non-Persistent Reserve Restricting**:
   - `userspace-dp/src/nat/allocator.rs:1114,:1224`: `persistent_by_source` maps `PersistentSourceKey` to lease objects carrying `active_flows` (co-holder count), which can be transferred as an atomic unit.
   - `allocator.rs:1654,:1682-1701`: `reserve_flow` sets `persistent_key: None`. If called sequentially for co-holder flows (F1, F2) sharing tuple P, F1's port reservation causes F2 to hit the bitmap occupancy failure at `:1688-1690`. Restricting `reserve_flow` to non-persistent allocations and routing persistent leases through lease-object migration eliminates this failure mode.
