# AGY hostile plan-review — round 102 (v10.19.0)

Reviewer: AGY (direct binary). Verdict: SOUND — verified every named site in the contract block, the consumer set, the displaced-set producers, the ValidatorRefused/UpsertRefused accounting, and the invalidation timing against the binding/batch ownership.

## Verbatim review

SOUND

### 1. Verification of Named Code Sites in the §5.8 Contract Block
Every named file and line range specified in the consolidated normative §5.8 contract block of [`docs/research/6461-blind-rst/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1674-L1763) has been verified against the codebase:

- **`userspace-dp/src/afxdp/session_glue/mod.rs:1092-1121`**: [`materialize_shared_session_hit`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1092-L1121) is indeed the site where reactive materialization occurs. Updating it to return `(SessionLookup, MaterializeOutcome)` makes the outcome available before [`maybe_promote_synced_session`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1238-L1252) executes at [`userspace-dp/src/afxdp/session_glue/mod.rs:1235-1253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1235-L1253).
- **`userspace-dp/src/afxdp/session_glue/mod.rs:1254-1261` & `:1330-1344`**: The two return points in [`resolve_flow_session_decision`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1124-L1345) construct [`ResolvedFlowSessionDecision`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L564). Adding `materialization: MaterializeOutcome` (defaulting to `None`) covers all instantiation points of this type.
- **`userspace-dp/src/afxdp/poll_descriptor/mod.rs:509`**: Line 509 reads fields off `resolved` (such as `resolved.install_failed` and `resolved.created`). Hoisting `resolved.materialization` onto the descriptor dispatch context at this location preserves the outcome before `resolved` is reduced to `resolved.decision` at [`poll_descriptor/mod.rs:883`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L883).
- **`userspace-dp/src/afxdp/poll_descriptor/mod.rs:698-714`, `:768-784`, `:824-840`**: These three blocks are the exact invocation points of [`delete_terminal_filtered_session`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L477-L521) on host-inbound deny, filter-terminal drop, and `to-zone junos-host` policy deny.
- **`userspace-dp/src/afxdp/session_glue/mod.rs:477-581`**: Defines [`delete_terminal_filtered_session`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L477-L521) and [`delete_terminal_half`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L532-L582), which release source-NAT/NAT64 allocations, unpublish session-map/conntrack entries, delete local/shared table state, replicate deletes across workers, and emit Close deltas.
- **`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900-3959`**: Represents the flow-cache population block where `FlowCacheEntry::from_forward_decision` is built and inserted into `binding.flow.flow_cache`.
- **`userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662-4829`**: Defines the common `MissingNeighbor` seed block where NAT derivation, allocation, metadata construction, `install_with_protocol_with_origin`, and shared publication occur.
- **`userspace-dp/src/afxdp/worker/scratch.rs:19-32`**: Defines [`WorkerScratch`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/scratch.rs#L33-L45), confirming that reusable per-binding vectors are preallocated at worker initialization via `with_capacity` hints to enforce zero hot-path heap allocations.
- **`userspace-dp/src/afxdp/mod.rs:278-281`**: Establishes `const RX_BATCH_SIZE: u32 = 64;` with a compile-time assertion, bounding batch sizing across descriptor loop execution.
- **`userspace-dp/src/afxdp/shared_ops.rs:602-628`**: Contains the placeholder substitution in `lookup_session_across_scopes`, where fabric wire placeholders are checked and replaced by shared forward wire matches.
- **`userspace-dp/src/session/install.rs:295-322`**: Contains [`upsert_synced_with_origin`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L295-L340), which currently discards `_previous` (`let _previous = self.remove_entry(&key);`) and returns `bool`.
- **`userspace-dp/src/session/entry.rs:245-253`**: Defines [`is_peer_synced`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L245-L250) (`SyncImport | SharedMaterialize | WorkerLocalImport`), confirming that `SharedPromote` is non-peer (`!is_peer_synced()`).
- **`userspace-dp/src/afxdp/worker/lifecycle.rs:53-55`, `:209-225`**: Demonstrates the `split_at_mut` pattern in [`poll_binding_level`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/lifecycle.rs#L53-L56) exposing `left` and `right` sibling bindings alongside `binding`, and the `poll_binding_process_descriptor` call site.

---

### 2. OverdueSkipped Consumer Set Walkthrough
The §5.8 contract block specifies five normative consumers for `MaterializeOutcome::OverdueSkipped`:

1. **Terminal Teardown Guard**: At [`poll_descriptor/mod.rs:698-714`, `:768-784`, `:824-840`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L698-L714), an `OverdueSkipped` outcome bypasses [`delete_terminal_filtered_session`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L477-L521). This prevents tearing down existing session state, releasing NAT allocations, or publishing Close deltas under S2's identity when materialization was skipped due to an overdue probation entry.
2. **Anchor Commit Hook**: The `TcpSeqAnchor` update hook in the commit arm does not write for `OverdueSkipped` dispatches.
3. **Flow-Cache Insert Suppression**: At [`poll_descriptor/mod.rs:3900-3959`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3900-L3959), flow-cache entry creation is suppressed so unvalidated/overdue state does not contaminate the fast path.
4. **Probation Clear + Refresh Protection**: Probation clear and refresh hooks never execute for an overdue entry, preventing clock resurrection or premature probation clearing.
5. **Ownership Promotion Guard**: `maybe_promote_synced_session` is guarded by the §5.5 probation flag on entry `K`, keeping `K` installed without origin promotion.

*Permitted Consumers*: Traffic accounting ([`poll_descriptor/mod.rs:3494-3503`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3494-L3503)) advances packet counters as specified by #2501 semantics. Packet delivery and buffering consume S2's decision ([`poll_descriptor/mod.rs:5057-5068`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L5057-L5068)), while deferred RST teardown ([`session_glue/mod.rs:863-875`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L863-L875)) returns `false` by design. Inside `MissingNeighbor` handling ([`poll_descriptor/mod.rs:4662-4829`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4662-L4829)), `OverdueSkipped` routes directly into the `ExistingResolved` buffer-only arm, avoiding the common seed block.

---

### 3. Displaced-Set Producers and `ValidatorRefused` / `UpsertRefused` Accounting
The displaced-identity tracking contract using `displaced: BoundedIdentitySet` is sound and allocation-free:

- **Preallocated Capacity**: `BoundedIdentitySet` is stored in [`WorkerScratch`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/scratch.rs#L33-L45) with a maximum capacity of 3 identity families per transition $\times$ 64 descriptors ([`afxdp/mod.rs:278-281`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/mod.rs#L278-L281) `RX_BATCH_SIZE`), maintaining the zero-hot-path-allocation invariant.
- **OUT Parameter Integrations**: Placeholder substitution ([`shared_ops.rs:602-628`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L602-L628)) and [`upsert_synced_with_origin`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L295-L322) capture displaced identities via OUT parameters instead of discarding `_previous`.
- **Refusal Semantics**:
  - `ValidatorRefused`: Site-2c installation refusal against an active probation entry can displace a canonical predecessor during initial entry removal in `upsert_synced_with_origin`. `ValidatorRefused` carries that predecessor's full identity family.
  - `UpsertRefused`: Table-capacity refusal at site 2c displaces zero identities during installation. However, if the resolution subsequently attempts promotion via [`maybe_promote_synced_session`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1238-L1252) and [`update_session`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1350-L1370), `SharedPromote` (`!is_peer_synced()`, [`entry.rs:245-253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L245-L250)) can overwrite a non-peer predecessor. Recording the displaced predecessor during the promotion step ensures complete invalidation coverage.
  - `OverdueSkipped` and no-predecessor refusals carry an empty set.

---

### 4. Realizable Invalidation Timing vs. Binding/Batch Ownership
The invalidation workflow aligns with worker data ownership:

- **Per-Descriptor Current-Binding Invalidation**: In [`poll_descriptor/mod.rs:110-131`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L110-L131), descriptor processing mutably owns `binding` (`BindingWorker`). Draining the accumulated displaced set from `WorkerScratch` immediately after each descriptor's resolution—before early exits, flow-cache inserts, or advancing to the next descriptor—guarantees that subsequent descriptors in the same 64-descriptor batch do not encounter stale entries in the current binding's `flow_cache`.
- **Per-Batch Sibling Binding Fan-Out**: Sibling bindings (`left` and `right` in [`lifecycle.rs:53-55`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/lifecycle.rs#L53-L55)) belong to the same worker thread but separate `BindingWorker` instances. Invalidating sibling flow caches once per batch at the `poll_binding` level ([`lifecycle.rs:209-225`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/lifecycle.rs#L209-L225)) before the next RX batch prevents cross-binding stale cache hits.
- **Separation from Reap Routine**: Invalidation is explicitly excluded from the poll-loop reap routine ([`worker/loop_body/mod.rs:1481-1521`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L1481-L1521)), ensuring that cache eviction is driven directly by resolution events rather than delayed GC cycles.

---

### 5. Surviving Surface & Full-Document Sweep
- **Master Drift Compliance (§3.1)**: All cited baseline line numbers from `023f17a606d8` match current master `fff7a4ab5`. The removal of `cluster_peer_return_fast_path` by #6478 correctly eliminates site 6, and MissingNeighbor stage outcome wrapping by #6432 integrates cleanly with arm-head outcome branching.
- **Provenance & State Disciplines**: The rules governing local probation reaps, target-reciprocated companion propagation, and non-promotion of closing segments prevent cluster-wide state corruption and unintended Close delta emissions.
- **Document Consistency**: The SSOT block in §5.8 accurately reflects the surrounding architectural specifications (§5.1–§5.7), risk assessments (§8), test requirements (§9), and out-of-scope boundaries (§10).
