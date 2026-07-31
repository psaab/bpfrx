# AGY hostile plan-review — round 90 (v10.7.0)

Reviewer: AGY (direct binary: agy --print-timeout 11m --print, env -C worktree, built-in-file-tools-only; neutral doc-consistency framing). Verdict: SOUND — 8th consecutive AGY YES. Explicitly verified all three v10.7.0 folds (skip-install+rollback, adopt-S2-preserve-deadline, propagation skip) plus the spray allocation-neutrality, the wheel re-queue arithmetic (expire.rs:50-57 target_tick_for over preserved last_seen+expires_after), and the cleared-probation emission authority (SharedMaterialize origin stays peer-synced -> expire.rs:342-344 excludes Close even after clear).

## Verbatim review

SOUND

### Design Document Review: `docs/research/6461-blind-rst/plan.md` (v10.7.0)

---

### 1. Fold Verification Against Code and Document Text

1. **Section 5.6 Site-3 Supplement (Rollback/Skip Shape)**
   - **Document Trace:** [`docs/research/6461-blind-rst/plan.md:372`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L372), [`:1333-1354`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1333-L1354), [`:1417-1422`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1417-L1422).
   - **Code Base Verification:** [`userspace-dp/src/nat/source.rs:1548`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs#L1548), [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:4901-4909`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4901-L4909), [`userspace-dp/src/afxdp/poll_descriptor/session_admission.rs:83-87`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/session_admission.rs#L83-L87).
   - **Analysis:** SYN-bearing closing combinations (`SYN|RST`, `SYN|FIN`) bypass `strict_syn_check_drops_new_flow` ([`session_admission.rs:83-87`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/session_admission.rs#L83-L87) returns `false` because `has_syn` is true). Under `ResolvedWithoutLocalBacking` (RWoLB) re-entry or `ReplacedSyncedLocal` displacement, the packet tuple belongs to a peer-synced victim. The v10.7.0 fold specifies skipping session install and publication entirely and rolling back the freshly derived NAT allocation ([`nat/source.rs:1548`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs#L1548)). This matches the existing seed-refusal rollback discipline at [`poll_descriptor/mod.rs:4901-4909`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4901-L4909) (`rollback_source_nat_allocation`). No owned table entry or NAT reservation is held, and no generation-zero Close delta is generated ([`pkg/cluster/sync_conn_gen.go:176`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go#L176), [`:263`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go#L263)).

2. **Section 5.6 Site-2c (Adopt-Preserve Upsert Fields)**
   - **Document Trace:** [`docs/research/6461-blind-rst/plan.md:371`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L371), [`:1205-1222`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1205-L1222), [`:1410-1416`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1410-L1416).
   - **Code Base Verification:** [`userspace-dp/src/session/install.rs:295-433`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L295-L433).
   - **Analysis:** Re-materialization against an existing probation entry under the same canonical key executes `upsert_synced_with_origin` ([`install.rs:295`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L295)). Rather than skipping the upsert (which would leave decision/metadata stale when `ForwardingResolution` or zone/policy metadata changes, [`entry.rs:11-12`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L11-L12)), it adopts the shared map's current decision $S_2$ and metadata wholesale while preserving `last_seen_ns`, `expires_after_ns`, `probation = true`, and `closing = false, reset = false`. This prevents decision split-brain without resetting the $\le 20\text{ s}$ probation clock.

3. **Section 5.6 Fence (Companion Propagation Skip)**
   - **Document Trace:** [`docs/research/6461-blind-rst/plan.md:1256-1266`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1256-L1266), [`:1426`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1426), [`:1828-1831`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1828-L1831).
   - **Code Base Verification:** [`userspace-dp/src/session/mod.rs:1254-1276`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1254-L1276).
   - **Analysis:** `propagate_tcp_state_to_companion` ([`session/mod.rs:1232`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1232)) checks whether the propagation target has `probation == true`. If so, it skips state mutation, restamping, timeout recomputation, and wheel re-queuing entirely. This prevents an accepted close on live half $F$ from pushing probation companion $R$'s deadline out to $30\text{ s}$.

---

### 2. Edge-Case and Stress Analysis

1. **Closing-Flagged Packet Spray under RWoLB / ReplacedSyncedLocal:**
   - *Allocation Neutrality:* Each closing packet in a spray triggers source NAT derivation ([`nat/source.rs:1548`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs#L1548)), detects peer-synced provenance + closing flags, skips session creation, and invokes `rollback_source_nat_allocation` ([`poll_descriptor/mod.rs:4901-4909`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4901-L4909)). The derived pool allocation is immediately released back to the allocator. Net allocated pool ports = 0.
   - *CPU Churn:* CPU cost per packet is bounded to NAT derivation + immediate rollback. This is identical to standard seed refusal under `max_sessions` capacity limits and creates no persistent memory or table slot leaks.

2. **RWoLB Follow-up NON-Close Packet (Open Delta & HA Hazards):**
   - When a subsequent legitimate non-close packet arrives for the flow, it re-enters the miss pipeline, passes `#4400`, and installs as a `LocalMiss` session, emitting an `Open` delta over HA.
   - On the peer node, `installGenGuardV4` ([`pkg/cluster/sync_conn_gen.go:199-231`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go#L199-L231)) and `upsert_synced_with_origin` ([`install.rs:312`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L312)) evaluate incoming `Open` deltas against existing stored generations. If the peer already holds the authoritative entry, generation guarding ensures state stability without owner conflicts.

3. **Adopt-Preserve Wheel Re-Queue:**
   - In [`userspace-dp/src/session/expire.rs:50-57`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L50-L57), `push_to_wheel` computes `target_tick_for(now_ns, entry.last_seen_ns.saturating_add(entry.expires_after_ns))`.
   - By preserving both `last_seen_ns` and `expires_after_ns` during an adopt-preserve upsert, `last_seen_ns + expires_after_ns` evaluates to the exact original absolute deadline, ensuring the timer wheel tick calculation remains unchanged.

4. **Probation Clear Path & Emission Authority:**
   - When a committed non-close packet hits a probation entry, `probation` clears to `false`.
   - For an unpromoted `SharedMaterialize` entry, `removed.origin.is_peer_synced()` evaluates to `true` ([`userspace-dp/src/session/entry.rs:245-250`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L245-L250)).
   - At [`userspace-dp/src/session/expire.rs:342-344`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L342-L344), `!removed.origin.is_peer_synced()` evaluates to `false`. Thus, an unpromoted `SharedMaterialize` entry emits **no** `SessionDeltaKind::Close` on expiration. Only if the entry undergoes ownership promotion (`maybe_promote_synced_session`) to `LocalEstablished` does it gain Close emission authority.

---

### 3. Whole-Document Consistency Sweep

- **Site Table (§3):** Site 2b ([`plan.md:370`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L370)), Site 2c ([`plan.md:371`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L371)), Site 3 ([`plan.md:372`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L372)), and Site 9 ([`plan.md:378`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L378)) consistently reflect the v10.7.0 folds. Site 6 ([`plan.md:391`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L391)) accurately documents its deletion on master by `#6478`.
- **Drift Table (§3.1):** All line citations across `poll_descriptor/mod.rs`, `session_admission.rs`, `install.rs`, `expire.rs`, `shared_ops.rs`, and `nat/source.rs` match the worktree base `023f17a606d8` and map correctly to `fff7a4ab5`.
- **Core Mechanics (§5.5–§5.8):** All references to the retracted v10.6.0 shapes (alive probation install for RWoLB/ReplacedSyncedLocal and skip-the-upsert materialize) are explicitly qualified as retracted and superseded by v10.7.0 rules.
- **Invariants (§7) & Test Plan (§9):** Invariants on probation deadline integrity ([`plan.md:1594-1612`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1594-L1612)) and test cases ([`plan.md:1808-1846`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1808-L1846)) cover adopt-preserve materialize, companion propagation skipping, and RWoLB/ReplacedSyncedLocal skip-install + rollback.
- **Questions (§11):** Review questions in §11 accurately capture the v10.7.0 design posture.

---

### Summary

The document `docs/research/6461-blind-rst/plan.md` (v10.7.0) is complete, self-consistent, and rigorously aligned with the underlying dataplane implementation. It is ready to be implemented from.
