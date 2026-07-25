VERDICT: PLAN YES

### Q1: SOUND
**Evidence:**
- **Entry points covered:** Read permit acquired before any mutation across all ownership paths: `allocate_translation` (`userspace-dp/src/nat/allocator.rs:975`), deterministic PAT (`userspace-dp/src/nat/source.rs:1431`), deterministic NAT64 (`userspace-dp/src/nat/source.rs:995`), address-only round-robin (`userspace-dp/src/nat/source.rs:1523`), persistent address-only (`userspace-dp/src/nat/source.rs:1497`), `reserve_flow` / `reserve_address_only*` (`userspace-dp/src/nat/allocator.rs:1617, :1654`), release paths (`release_flow` `:1345`, `free_translated_port`), `rollback_flow` (`userspace-dp/src/nat/allocator.rs:1392`), and expiry GC (`userspace-dp/src/nat/allocator.rs:2302`).
- **Lock-free claim covered:** Read permit is taken prior to `occ.claim()` (`userspace-dp/src/nat/allocator.rs:1018`), eliminating the un-gated bitmap mutation trace.
- **Deadlock / Dual-record elimination:** Migration acquires WRITE permit on A, drains in-flight mutations, snapshots A's complete state into B under A's `live` lock (`userspace-dp/src/nat/allocator.rs:1034`), atomically publishes B via `Arc` swap (`afxdp/coordinator/snapshot_refresh.rs:397`), and closes A's gate. No cross-allocator mutex acquisition or lockstep dual-record is required.

### Q2: SOUND
**Evidence:**
- **Ordering & Park Mechanism:** Sender-side sweep advances cutoff on local queue success (`pkg/cluster/sync_conn_sweep.go:137, :185`). Receiver-side exact-epoch deferral parks the connection stream head-of-line on `install.admission_config_version` > receiver applied/applying high-water mark (`pkg/cluster/sync_conn_read.go:96, :298`).
- **Wire Schema & Per-entry Epochs:** §5.8 normative wire schema mandates per-entry identity stamps (`admission_config_version`, `persistent_nat`, `persistent_nat_permit`) on ALL wire emissions including initial install, periodic resend (`pkg/cluster/sync_conn_sweep.go:142`), and bulk (`pkg/cluster/sync_bulk.go:95`).
- **C1/C2 Expansion Handling:** Deferral prevents C1 (port 40000 limit) receiver bitmap from prematurely rejecting C2 (port 40001 limit) reservations before C2 is locally applied. Because deletes and installs share the FIFO connection stream, head-of-line parking guarantees deletes cannot bypass parked installs for the same key.

---

### NEW TRACES FOLDED OPEN IN v9.9.17

1. **Unapplied/Invalid Config Sync Buffer Overflow Reset Loop**
   - **Locations:** `docs/research/6461-blind-rst/plan.md:1063-1065`, `pkg/cluster/sync_conn_read.go:96`, `pkg/cluster/sync_bulk.go:95`
   - **Trace:** If a configuration update containing an expanded port range or persistent NAT rule fails validation or halts during application on the standby receiver (`configSyncFailing`), the receiver's applied high-water epoch remains stuck below $E_{future}$. The active node streams session `INSTALL` messages stamped with `admission_config_version = E_future`. The standby head-of-line parks the connection stream. As active session creation continues, the standby's bounded park buffer fills and overflows, triggering a connection reset (`sync_conn_read.go`). Upon reconnect, the standby requests a bulk resync (`sync_bulk.go:95`), causing the active node to re-emit the same $E_{future}$-stamped entries. The standby immediately parks the stream again, overflows, and enters an infinite connection reset/re-bulk loop.
AGY EXIT: 0
VERDICT: PLAN YES

### Q3 (rollback edge): SOUND
- **Lease Refcount & Port Protection**: In [allocator.rs:1392-1460](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L1392-L1460), `rollback_flow` handles a persistent key by decrementing `lease.active_flows` via `saturating_sub(1)` (line 1411).
- **Lease Teardown Logic**: `remove_lease` is set to `true` (line 1421) only if `active_flows == 0` **and** neither `activation_saw_completion` nor `activation_had_previous_lease` is `true`. For a co-holder RETAIN:
  - If other active flows remain (`active_flows > 0`), `remove_lease` remains `false`.
  - If the rolling-back co-holder dropped `active_flows` to 0 on an existing lease (`activation_had_previous_lease` or `activation_saw_completion` is `true`), `insert_expiry` restores/sets the expiration index (lines 1413–1420), while `remove_lease` remains `false`.
- **Port Bit Preservation**: `free_translated_port` (line 1428) is called strictly within `if remove_lease`. Thus, rolling back a co-holder RETAIN decrements the lease refcount without freeing the port or destroying existing lease ownership shapes.

### Q4 (inventories + capability gate): SOUND
- **Wire Schema & Inventory Alignment**: In `docs/research/6461-blind-rst/plan.md` §5.8:
  1. *INSTALL tail*: [plan.md:2254-2256](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2254-L2256) lists `(origin_process_nonce, flow_incarnation_id, stable_rule_id_hash, admission_config_version, persistent_nat, persistent_nat_permit)`.
  2. *Go sidecar store*: [plan.md:2279-2282](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2279-L2282) lists `(origin_process_nonce, flow_incarnation_id, row_version, stable_rule_id_hash, admission_config_version, persistent_nat, persistent_nat_permit)`.
  3. *Atomic snapshot tuple*: [plan.md:2293-2294](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2293-L2294) lists `(BPF/NAT row, identity, row_version, stable_rule_id_hash, admission_config_version, persistent_nat, persistent_nat_permit)`.
  4. *Shared-map inventory*: [plan.md:2345-2348](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2345-L2348) lists `(last_touch_ns, expires_after_ns, flow_incarnation_id, stable_rule_id_hash, admission_config_version, persistent_nat, persistent_nat_permit)`.
  All four inventories consistently include `(persistent_nat, persistent_nat_permit)`.
- **Capability Gate**: In [capabilities.go:87-89](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/capabilities.go#L87-L89), clustered persistent source NAT is commit-time rejected via `addReason(persistentSourceNATHAUnsupportedReason)` when `cfg.Chassis.Cluster != nil && userspaceConfigUsesPersistentSourceNAT(cfg)`, exactly matching the plan.

---

### NEW traces opened by v9.9.17 additions
*None.* The v9.9.17 additions (receiver-side head-of-line epoch deferral, transaction rollback via `rollback_flow` RAII guard, and disarmed capability gating) cleanly close the epoch-skew and import orphan edges without opening new traces.
AGY EXIT: 0
