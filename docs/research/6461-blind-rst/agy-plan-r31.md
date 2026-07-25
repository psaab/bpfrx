VERDICT: PLAN YES

### Question Verification & Soundness Analysis

#### Q1 (temporary stop/rebind, round-30 Codex B3 fold): SOUND
- **File:Line Evidence**:
  - [stop_workers.rs:15](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/handlers/stop_workers.rs#L15): `stop_workers::handle` calls `guard.afxdp.stop()`, invoking `stop_inner(true)`.
  - [rebind.rs:18-37](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/handlers/rebind.rs#L18-L37): Documents why `rebind` avoids calling `stop_inner(true)` and delegates worker stop/quiesce to `reconcile_status_bindings` -> `tear_down`.
  - [coordinator/mod.rs:429, 645, 675, 709](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs#L429): `stop_inner` performs worker `stop_and_clear` (:645), map FD clears (:675), and conditional `sessions.synced` wiping (:709).
  - [teardown.rs:55, 80, 81](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs#L55): `tear_down` captures `had_live_workers` and `synced_sessions` before invoking `stop_inner(false)`.
  - [status.rs:377](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/helpers/status.rs#L377): `reconcile_status_bindings` routes disarmed forwarding to `state.afxdp.stop()`.
  - [bringup.rs:421, 434](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs#L421): `replay_preserved_sessions` replays preserved synced entries into worker queues and session maps.
- **Analysis**:
  1. Preserving synced session maps across a temporary stop does not contradict the #1866 rationale ([coordinator/mod.rs:630](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs#L630)); #1866 specifically targeted WireGuard control-thread tombstones (`wg_control_threads`), not synced session entries.
  2. Under the plan's generalized two-phase quiesce/handoff at worker stop time, worker quiesce occurs when workers actually stop. `had_live_workers` sampling in `teardown.rs:55` remains intact for reconcile paths.
  3. Rebind bring-up replays preserved synced entries through `replay_preserved_sessions` ([bringup.rs:421](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs#L421)) using the identical mechanism as reconcile.

---

#### Q2 (persistent-lease peer INSTALLs, round-30 Codex B2 fold): SOUND
- **File:Line Evidence**:
  - [allocator.rs:1106-1130, 1114, 1224, 1318, 1654-1700](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L1114): `allocate_translation` derives `persistent_key` (:1114) and reuses leases (:1224); `reserve_flow` (:1654) sets `persistent_key: None` (:1695).
  - [upsert_synced.rs:64, 90-96, 112](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L64): `upsert_synced_with_origin` runs `reserve_synced_source_nat_allocation` (:90) prior to worker map publication (:112).
  - [source.rs:214-224, 868](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs#L214-L224): `SourceNatFlowKey::persistent_source_key` computes `PersistentSourceKey` deterministically from flow tuples and `PersistentNatPermit`.
  - [tests_pool.rs:2536](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/tests_pool.rs#L2536): `pool_snat_persistent_rollback_keeps_lease_reused_by_another_flow` verifies persistent lease sharing across distinct flows.
- **Analysis**:
  1. **Derived-key claim**: Correct. `SourceNatFlowKey::persistent_source_key` ([source.rs:214-224](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs#L214-L224)) is a pure function of flow parameters and the pool permit, allowing the standby to derive the exact same `PersistentSourceKey` as the active node for all persistent pool shapes (`AnyRemoteHost`, `TargetHost`, `TargetHostPort`).
  2. **Standby-gap liveness**: Rejecting the install on allocation failure prevents publishing misdelivering NAT aliases. The standby missing an un-installed copy until re-sync is safe because the standby is not actively forwarding for that resource group.

---

#### Q3 (allocation-mode compatibility + dual-record bridge, round-30 Codex B1a fold): SOUND
- **File:Line Evidence**:
  - [source.rs:327-334, 726](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs#L327-L334): `SourceNatPoolAllocatorKey` omits allocation mode, permitting exact-key allocator reuse (:726) across PAT vs address-only mode changes.
  - [allocator.rs:999, 1727](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L999): PAT allocation checks `occupancy` bitmaps (:999), while `reserve_address_only` checks `address_only_owners` (:1727).
- **Analysis**:
  1. Incorporating allocation mode into the collision domain key ensures mode changes invalidate old escrow tokens and trigger re-resolution rather than reusing mismatched allocators.
  2. Structural cross-mode occupancy checks in both directions prevent issuance of identical public reverse tuples across PAT and address-only modes.
  3. The dual-recording bridge records retain operations in both allocators (or retokenizes under worker quiesce), ensuring `release_source_nat_allocation` drains refcounts through both allocators cleanly.

---

#### Q4 & Q5 (§9 mixed-version matrix & selector inventories, round-30 Codex H4 & M5 folds): SOUND
- **File:Line Evidence**:
  - `plan.md:1583-1605, 2444-2453`: Replaced all old fallback clauses. Confirms that identity-dependent deletes (Close, invalidation, conditional deletes) are suppressed entirely toward legacy/unnegotiated peers—no sender-initiated gen-based deletes are sent to legacy receivers or locally authoritative entries.
  - `plan.md:2070-2092` (§5.8): Aligned §5.8 wire schema, Go sidecar store, and NODE-LOCAL shared-map schema to carry `stable_rule_id_hash` and `admission_config_version` alongside `flow_incarnation_id` and `origin_process_nonce`.
- **Analysis**:
  - The mixed-version matrix and selector inventories across all three sites (§5.8 wire schema, Go sidecar store, NODE-LOCAL shared-map schema) are complete and consistent.

---

### NEW Traces / Findings
None. The v9.9.15 folds cleanly resolve all edge cases identified in prior review rounds without opening new race conditions or safety regressions.
AGY EXIT: 0
