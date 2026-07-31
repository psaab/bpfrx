# AGY hostile plan-review — round 96 (v10.13.0)

Reviewer: AGY (direct binary). Verdict: SOUND. Verified the parity-not-correctness fold and the purge-aftermath documentation, the cache-suppression mechanism (the purging-dispatch signal reaching the insert point), the overdue-K local-only removal's reference integrity (indexes, counted class, wheel hints, no NAT/BPF/delta), and stress-tested the close spray, close-then-ACK, RG-activation, and cold-at-capacity cases. Full-document consistency sweep clean.

## Verbatim review

SOUND

### 1. Verification of Round-96 Folds Against Code base

- **Fold 1: Parity-not-correctness (Cold-Path Seed Transaction Rollback Leak)**
  - **Traces**: [`userspace-dp/src/nat/mod.rs:123-133`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs#L123-L133), [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:4890-4909`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4890-L4909), [`userspace-dp/src/nat/allocator.rs:1398-1404`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L1398-L1404).
  - **Verification**: `NatDecision::merge` (`nat/mod.rs:125-133`) uses `self.rewrite_src.or(other.rewrite_src)` to prefer existing fields set on `self` (the retained lookup decision carrying P1). When a seed transaction at capacity triggers `seed_install_refused` (`poll_descriptor/mod.rs:4890-4909`), `rollback_source_nat_allocation` passes `pending_decision.nat` (carrying P1) to `allocator.rs:1398-1404`. `rollback_flow` checks `if existing.translated != translated { return false; }`. Because `existing.translated` holds the newly allocated P2 while `translated` holds P1, the equality fails and `rollback_flow` returns `false`, leaking P2 in `live_by_flow`. The document's classification of this behavior in §7 as pre-existing upstream master behavior is accurate.

- **Fold 2: One Hardening Delta (Purging Dispatch Flow-Cache Insert Suppression)**
  - **Traces**: [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:298-327`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L298-L327), [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900-3959`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3900-L3959).
  - **Verification**: In `poll_descriptor/mod.rs:298-327`, the flow cache is consulted before slow-path session resolution. During a purging dispatch, setting `install_failed = true` on `ResolvedFlowSessionDecision` sets `flow_cache_install_failed = resolved.install_failed` at `poll_descriptor/mod.rs:509`. This directly gates line 3900 (`if !flow_cache_install_failed`), suppressing `FlowCacheEntry::from_forward_decision` insertion for the released P1 decision. This prevents caching a sessionless descriptor with released translations, ensuring the subsequent packet clean-misses and installs fresh.

- **Fold 3: Retraction of Overdue Probation Entry In-Place Adopt**
  - **Traces**: [`userspace-dp/src/session/mod.rs:1627-1663`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1627-L1663), [`userspace-dp/src/session/install.rs:434-447`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L434-L447), [`userspace-dp/src/session/entry.rs:242-269`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L242-L269).
  - **Verification**: Retracting the in-place adopt for overdue probation entries avoids complex state transitions. An in-place write would require atomic reindexing across NAT/owner-RG changes (`session/mod.rs:1627-1663`), handling presence-based counted-class transitions (`install.rs:434-447`), and evaluating origin authority (`entry.rs:242-269`). Replacing this with local-only removal cleanly unbinds the overdue entry without mutating state structures.

- **Fold 4: Documented Corners and Retention Bounds**
  - **Traces**: [`userspace-dp/src/afxdp/session_glue/promote.rs:99-139`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L99-L139), [`userspace-dp/src/session/mod.rs:1480-1530`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1480-L1530), [`userspace-dp/src/afxdp/worker/mod.rs:375-401`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs#L375-L401), [`userspace-dp/src/afxdp/flow_cache.rs:767-780`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/flow_cache.rs#L767-L780).
  - **Verification**: `promote_synced_with_origin` (`promote.rs:99-139`) and `push_delta` (`session/mod.rs:1480-1530`) confirm that when a retained row's RG activates locally, the next non-close packet promotes the row and emits an Open delta without re-reserving SNAT. `SyncedSessionEntry` (`worker/mod.rs:375-401`) carries no expiration timestamp, showing that shared rows hold no deadline and depend on explicit non-close purges or peer deletes.

- **Fold 5: Arm-Head Outcome Naming Taxonomy**
  - **Traces**: [`userspace-dp/src/session/install.rs:123-125`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L123-L125), [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:4634-4656`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4634-L4656).
  - **Verification**: The separation between arm-head resolve outcomes (`ExistingResolved`, `PurgedRetained`, `SeedEligible`) and seed transaction execution results (`SeedInstalled`, `SeedRefused`) is sound. `install.rs:123-125` (`self.len() >= self.max_sessions`) and `poll_descriptor/mod.rs:4634-4656` (NAT64 cold-start drops) demonstrate that `SeedRefused` is a runtime result of `SeedEligible`.

---

### 2. Cache-Insert Suppression Signal Flow (Checklist b)

- **Traces**: [`userspace-dp/src/afxdp/session_glue/mod.rs:1178-1261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1178-L1261), [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:509`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L509), [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3900).
- **Mechanical Soundness**: When `purge_translated_synced_hit` runs during a purging dispatch, returning `install_failed = true` in `ResolvedFlowSessionDecision` sets `flow_cache_install_failed = resolved.install_failed` at `poll_descriptor/mod.rs:509`. At line 3900, `if !flow_cache_install_failed` evaluates to `false`, reliably blocking `FlowCacheEntry::from_forward_decision` from caching the released P1 decision.

---

### 3. Local-Only Overdue Probation Entry Removal (Checklist c)

- **Traces**: [`userspace-dp/src/session/mod.rs:349`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L349), [`userspace-dp/src/session/install.rs:445-447`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L445-L447).
- **Reference Integrity**:
  1. **Table/Indexes**: `remove_entry` removes `K` from `entries` and `key_to_handle`, cleaning up `forward_nat_index` and `owner_rg_sessions`.
  2. **Counted Class**: `session_limit_dec` decrements the per-IP count as expected.
  3. **Wheel Hints**: Stale wheel hints pointing to `K`'s handle safely miss or encounter generation mismatches during wheel ticks.
  4. **NAT/BPF/Deltas**: No source NAT allocation release runs, no BPF map deletion occurs, and no Close delta is emitted.
  5. **Forwarding**: The current packet forwards using the materialized shared decision in hand, and subsequent packets clean-miss to re-materialize fresh.

---

### 4. End-State Stress Testing (Checklist d)

1. **Close Spray on Retained Row**: The close-aware purge gate skips transient purging for closing packets, returning `ExistingResolved`. The packet buffers with decision P1 and transmits upon neighbor resolution. Validation against untrusted peer-synced state soft-refuses, keeping `closing = false` without emitting Close deltas.
2. **Close-then-ACK Sequence**: The initial close retains the row. The subsequent ACK (non-close) triggers a transient purge, releasing P1 and forwarding without installation. The hardening delta sets `flow_cache_install_failed = true`, preventing flow-cache insertion. The next packet clean-misses and installs fresh P2.
3. **RG-Activation Sequence**: Local RG activation causes `should_keep_synced_hit_transient` to return `false`. A subsequent non-close packet promotes the row to `SharedPromote` and emits an Open delta with P1 without re-reserving SNAT, matching documented §7 behavior.
4. **Purged Cold Packet at Capacity**: A purged cold packet triggers a seed transaction. When `SessionTable` capacity is reached (`install.rs:123-125`), `seed_install_refused` calls `rollback_flow` (`allocator.rs:1398-1404`). `rollback_flow` fails to match P1 (from `merge`) against P2, safely retaining P2 in `live_by_flow` as documented.

---

### 5. Full-Document Consistency Sweep (Checklist e)

- Document version `v10.13.0` maintains internal consistency across §1 through §11. All line citations, outcome classifications (`ExistingResolved`, `PurgedRetained`, `SeedEligible`, `SeedInstalled`, `SeedRefused`), and control-flow logic align with the underlying code base.
