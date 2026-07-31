# AGY hostile plan-review — round 95 (v10.12.0)

Reviewer: AGY (direct binary). Verdict: SOUND. Verified the master-split claim against the arm code, the corrected retention bound (no deadline on the shared row; no removal at local expiry), the reindex/field contract against refresh_for_ha_transition and remove_entry's no_index_points_at assertion, and stress-tested the close spray, the close-then-ACK corner, and the capacity-exhaustion seed rollback. Full-document consistency sweep clean.

## Verbatim review

SOUND

### 1. Verification of Master-Split Purged-Class Dispatch (Checklist Item a)

Upstream master's exact dispatch behavior for a purged retained hit has been verified against the DP source:

1. **Transient Purge Execution**: When a peer-synced translated forward entry is hit and `should_keep_synced_hit_transient` evaluates to `true` ([`userspace-dp/src/afxdp/session_glue/mod.rs:1178-1180`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1178-L1180)), `purge_translated_synced_hit` ([`session_glue/mod.rs:1182-1192`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1182-L1192)) removes the local and shared synced sessions and un-indexes the translated source port ([`userspace-dp/src/afxdp/session_glue/promote.rs:181-207`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L181-L207)).
2. **Lookup Decision Return**: `resolve_flow_session_decision` sets `resolved = hit.lookup.clone()` ([`session_glue/mod.rs:1194-1196`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1194-L1196)) and returns `Some(ResolvedFlowSessionDecision)` with `created: false` ([`session_glue/mod.rs:1254-1261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1254-L1261)). No session entry is installed into `SessionTable` during this resolve step.
3. **Warm Next-Hop Branch**: If the next-hop L2 address is resolved, `decision.resolution.disposition` is `ForwardingDisposition::ForwardCandidate` (or `Forward`). In [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:412-510`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L412-L510), `poll_descriptor` receives `created: false`, bypasses creation telemetry, forwards the packet on the retained lookup decision, and performs no table installation.
4. **Cold Next-Hop Branch**: If the next-hop L2 address is unresolved, `looked_up_resolution` sets `decision.resolution.disposition` to `ForwardingDisposition::MissingNeighbor`. The packet reaches the `MissingNeighbor` arm at [`poll_descriptor/mod.rs:4034`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4034).
5. **Transient Seed Transaction**: In [`poll_descriptor/mod.rs:4662, :4745-4761, :4780-4795`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4662), a non-closing packet executes the seed path: it derives/allocates a fresh source NAT translation (`source_nat_decision_for_flow`), builds missing-neighbor session metadata, and calls `sessions.install_with_protocol_with_origin(..., SessionOrigin::MissingNeighborSeed, ...)`.
6. **No Open Delta Emission**: [`userspace-dp/src/session/entry.rs:272-274`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L272-L274) defines `origin.is_transient_local_seed()` as `true` for `MissingNeighborSeed`. In [`userspace-dp/src/session/install.rs:225, :234`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L225), `let counted = !metadata.is_reverse && !origin.is_transient_local_seed();` evaluates `counted` to `false`. Consequently, `push_delta(SessionDeltaKind::Open)` is skipped.
7. **Clean Miss Deferred Install**: When the neighbor subsequently resolves, a subsequent packet hits a clean miss and executes the standard `ForwardFlow` path, installing the full session entry and emitting the `Open` delta exactly as upstream master specifies.

The plan's master-split model in §5.2 / §5.5 and open question #1 resolution in §11 accurately reflects upstream master behavior.

---

### 2. Verification of Corrected Retention Bound (Checklist Item b)

The retention bound specification in Section 7 has been verified against the HA and worker data structures:

1. **Shared Row Field Contract**: [`SyncedSessionEntry`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs#L375-L401) ([`userspace-dp/src/afxdp/worker/mod.rs:375-401`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs#L375-L401)) contains only `key`, `decision`, `metadata`, `origin`, `protocol`, `tcp_flags`, `generation`, and `session_id`. It carries no `last_seen_ns`, `expires_after_ns`, or wheel timing structures.
2. **Local Worker Expiry Scope**: Local worker timing wheel expiry ([`userspace-dp/src/session/expire.rs:342-344`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L342-L344)) operates exclusively on the worker's local slab (`SessionTable`). Local expiry removes local replicas but does not mutate or clear the `shared_sessions` (`synced`) map.
3. **Shared Row Cleanup Triggers**: Removal of a shared entry from `shared_sessions` occurs only via:
   - Synchronized HA delete from the primary node (`delete_synced_session_gen` at [`userspace-dp/src/afxdp/ha/session_import.rs:243-320`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs#L243-L320)), or
   - A resolve-time transient purge (`purge_translated_synced_hit`) triggered by a non-closing packet.
4. **Retention Bound**: Under the close-aware demote gate, a reservation-conflicted shared row retains its state until either a non-closing packet triggers a transient purge or the peer issues a synchronized delete. Retention is bounded by the peer-side lifetime of the row, not by local worker expiry.

---

### 3. Verification of Atomic Reindex & Exhaustive Field Contract (Checklist Item c)

The overdue-K adopt reindex and field contract specification in §5.5 has been verified against existing session table mutation patterns:

1. **Reindex Precedent**: In [`userspace-dp/src/session/mod.rs:1627-1663`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1627-L1663) (`refresh_for_ha_transition`), updating an entry's `decision` and `metadata` requires checking whether `nat`, `is_reverse`, or `owner_rg_id` changed. If changed, `self.remove_forward_nat_index_parts(key, handle, old_nat, old_is_reverse)` and `remove_owner_rg_index_entry` must be called to purge old index references before writing new fields, followed by `index_forward_nat_key_parts`.
2. **Secondary Index Removal Invariant**: In [`userspace-dp/src/session/mod.rs:1750-1805`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1750-L1805) (`remove_entry`), index cleanup relies on `record.entry.decision.nat` and `record.entry.metadata.owner_rg_id`. Overwriting decision/metadata without reindexing leaves stale handles in `forward_nat_sessions` and `owner_rg_sessions`. On subsequent removal, cleanup using the updated fields fails to remove the old index entry, triggering `debug_assert!(self.no_index_points_at(handle))` at [`session/mod.rs:1802`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1802).
3. **Field Contract Compliance**: The plan specifies that in-place overdue-K adopt executes an atomic reindex, adopting incoming decision/metadata while preserving existing `origin` (`SharedMaterialize`), `session_id`, `install_epoch`, `counters`, `hold state`, and verbatim `last_seen_ns`/`expires_after_ns` without wheel re-queuing.

---

### 4. Stress-Testing End-State Failure Modes (Checklist Item d)

1. **Close Spray on a Retained Row**:
   - *Behavior*: A close packet (RST/FIN) matching a retained row hits the close-aware gate and takes `ExistingResolved`. It does not trigger `purge_translated_synced_hit`.
   - *State*: Lifetime, ownership, anchor, and delta emission posture remain unmutated. Accounting fields (`counters` and `observed_tcp_flags` at [`userspace-dp/src/session/mod.rs:1177-1210`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1177-L1210)) advance as a telemetry-only update.
2. **Close-then-ACK Cache Corner**:
   - *Behavior*: A close packet arrives first, hits the close-aware gate, does not purge, and forwards/buffers on the retained lookup. A subsequent ACK packet (non-closing) arrives and evaluates `should_keep_synced_hit_transient` to `true`.
   - *State*: The ACK packet executes `purge_translated_synced_hit`. If the next hop is warm, it forwards on the retained lookup without table installation; if cold, it enters the `MissingNeighbor` seed transaction and installs `MissingNeighborSeed`. A subsequent packet on a clean miss installs `ForwardFlow` with an `Open` delta.
3. **Purged Packet at Cold Neighbor with Capacity Exhaustion**:
   - *Behavior*: A purged non-closing packet with a cold next hop enters the `MissingNeighbor` arm ([`poll_descriptor/mod.rs:4034`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4034)) and attempts `sessions.install_with_protocol_with_origin`.
   - *State*: When the table is full (`self.len() >= self.max_sessions`), `install_with_protocol_with_origin` returns `false` ([`userspace-dp/src/session/install.rs:123`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L123)), setting `seed_install_refused = true` ([`poll_descriptor/mod.rs:4679`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4679)). The SNAT allocation rolls back, pending-neighbor buffering is skipped, and the descriptor is recycled to `scratch_recycle`, preventing leaks or state corruption.

---

### 5. Full-Document Consistency Sweep (Checklist Item e)

A full sweep of [`docs/research/6461-blind-rst/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md) (v10.12.0) confirmed document-wide consistency:

- All section cross-references (§3.1, §5.2, §5.5, §5.6, §7, §9, §10.6, §11) are internally aligned.
- All inline `file:line` citations accurately map to the `023f17a606d8` citation base, with master deltas tracked in §3.1.
- No un-updated legacy text from earlier rounds remains.

### Summary

The design document `docs/research/6461-blind-rst/plan.md` (v10.12.0) is consistent with the codebase and verified sound across all checklist items.
