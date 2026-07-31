# AGY hostile plan-review — round 99 (v10.16.0)

Reviewer: AGY (direct binary). Verdict: SOUND. Verified the scoped parity claim against the pre-purge lookup ordering, the OverdueSkipped transport + five-consumer set + ExistingResolved composition, the full alias set against the lookup/reply code (no accepted key shape omitted), and the saturating arithmetic. No new findings.

## Verbatim review

SOUND

### 1. Round-99 Fold Verification Against Code

Each of the five round-99 folds in `docs/research/6461-blind-rst/plan.md` (v10.16.0) has been verified against the codebase:

1. **Purge Parity Scope & Deliberate Delta**:
   - **Code Base**: In [`userspace-dp/src/afxdp/session_glue/mod.rs:1157-1196`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1157-L1196), `lookup_session_across_scopes` ([`userspace-dp/src/afxdp/shared_ops.rs:594-635`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L594-L635)) runs before the transient purge check (`should_keep_synced_hit_transient`). In [`userspace-dp/src/session/lookup.rs:105-128`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L105-L128) and [`userspace-dp/src/session/lookup.rs:198-218`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L198-L218), upstream marks `closing` / `reset` and propagates the shortened 2s/30s lifetime to its companion via [`userspace-dp/src/session/mod.rs:1232-1277`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1232-L1277) prior to `purge_translated_synced_hit`.
   - **Plan Alignment**: The plan accurately documents that the demote gate refuses the mark on anchorless peer-synced entries during that pre-purge lookup. Consequently, while `purge_translated_synced_hit` removes the local matched entry, the reverse replica lingers on its ordinary peer-synced trajectory (inactivity timeout) instead of being pulled onto the short closing window. The plan correctly categorizes this single delta as the §2 absorbing-state residual applied to this path.

2. **`OverdueSkipped` Transport & Consumer Set**:
   - **Code Base**: [`userspace-dp/src/afxdp/shared_ops.rs:563-578`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L563-L578) defines `ResolvedFlowSessionDecision`.
   - **Plan Alignment**: The plan adds `overdue_skipped: bool` to `ResolvedFlowSessionDecision` to carry the outcome cleanly. All 5 downstream state consumers are explicitly gated, while `#2501` packet accounting is preserved.

3. **Full Alias Set & Adoption Invalidation**:
   - **Code Base**: Lookup and reply matching across [`userspace-dp/src/session/lookup.rs:62-100`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L62-L100), [`userspace-dp/src/session/lookup.rs:222-250`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L222-L250), [`userspace-dp/src/session/lookup.rs:253-315`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L253-L315), and [`userspace-dp/src/session/key.rs:19-26`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs#L19-L26) index and validate canonical keys, reverse companions, reverse-translated aliases, forward-wire aliases, and reply-match tuples (`reverse_wire_key` and `reverse_canonical_key`).
   - **Plan Alignment**: The plan specifies flow-cache invalidation across all 5 key categories at reap time, and requires invalidating the prior identity's full alias set at adopt time whenever an S1→S2 transition alters NAT or orientation.

4. **Conceded-Chain Rationale Correction**:
   - **Code Base**: Primary miss installs at [`userspace-dp/src/session/install.rs:113-200`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L113-L200) seed `FreshPrimary` entries.
   - **Plan Alignment**: §5.6 site-3 supplement and §7 correctly explain that state creation on this path is constructor-side (SYN or SYN|close clean miss). A closing flag on the second packet only accelerates the fresh entry's own reap; the demote gate engages on live anchor-carrying sessions.

5. **Saturating Arithmetic**:
   - **Code Base**: Timer wheel target tick calculations use `entry.last_seen_ns.saturating_add(entry.expires_after_ns)` in [`userspace-dp/src/session/expire.rs:50-57`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L50-L57).
   - **Plan Alignment**: Candidate deadline additions in §5.6 (`min(K.last_seen_ns.saturating_add(K.expires_after_ns), now_ns.saturating_add(...))`) use `saturating_add` consistently.

---

### 2. OverdueSkipped Transport & Consumer Set Walk

Carrying `overdue_skipped: bool` inside `ResolvedFlowSessionDecision` ([`shared_ops.rs:563-578`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L563-L578)) covers all downstream consumers without ambiguity:

1. **Terminal Teardown**: Suppressed (no local session was installed or returned).
2. **Anchor Commit Hook**: No write (no update to `TcpSeqAnchor` on overdue entries).
3. **Flow-Cache Insertion**: Suppressed (prevents caching a sessionless decision, matching `install_failed` semantics).
4. **Probation Clear + Refresh**: Never fires when `D <= now_ns` (prevents resurrecting an overdue entry for a full established timeout).
5. **Ownership Promote**: Cannot engage (probation-gated, no local entry returned).
6. **MissingNeighbor Composition**: When a packet resolves with `overdue_skipped` and has a `MissingNeighbor` disposition, the disposition arm branches at the arm head into `ExistingResolved` (live-backed, buffer-only). It uses the resolver's stored decision and bypasses the seed block (allocator state, NAT/NPT derivation, metadata, counters, install, and publication remain untouched).
7. **Traffic Accounting**: `#2501` packet accounting (`account_packet`) runs for forwarded packets on the live session path, maintaining volume telemetry.

---

### 3. Full Alias Set Verification

The lookup and reply-matching paths in [`userspace-dp/src/session/lookup.rs`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs) accept five key shapes:
- **Canonical Primary Key**: `record.key` ([`lookup.rs:92`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L92)).
- **Reverse Companion Key**: `reverse_session_key(key, nat)` ([`lookup.rs:205`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L205), [`key.rs:173-205`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs#L173-L205)).
- **Reverse-Translated Alias**: `translated_session_key(key, nat)` via `reverse_translated_index` ([`lookup.rs:64`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L64), [`lookup.rs:307-315`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L307-L315)).
- **Forward-Wire Alias**: `forward_wire_key(key, nat)` via `forward_wire_index` ([`lookup.rs:253-294`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L253-L294)).
- **Reply-Match Tuples**: `reverse_wire_key` and `reverse_canonical_key` via `nat_reverse_index` ([`lookup.rs:222-250`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L222-L250), [`key.rs:19-26`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs#L19-L26)).

No accepted key shape is omitted from the plan's flow-cache invalidation set in §5.6 / §5.8 / §9.

---

### 4. Stress Test of the Surviving Surface & Full-Document Consistency

- **Purge Path Equivalence**: The transient-purge path is master-verbatim except for the demote gate's explicit refusal of the mark on anchorless peer-synced entries. The resulting replica-lifetime residual is documented in §2 and §5.2 (iv).
- **Arm-Head Outcomes**: The `MissingNeighbor` arm-head outcomes (`ExistingResolved`, `PurgedRetained`, `SeedEligible`, with `SeedInstalled`/`SeedRefused` as results) align with the typed resolution flow in [`userspace-dp/src/afxdp/poll_descriptor/mod.rs`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs).
- **Probation & Adopt Discipline**: Adopt-S2 preserves the minimum absolute deadline using `saturating_add` and `saturating_sub` ([`expire.rs:50-57`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L50-L57)). Overdue entries (`D <= now_ns`) skip upsert, re-queue, and commit-hook refresh, allowing scheduled GC reaping without clock extension.

---

### 5. Summary of Review Findings

1. **`userspace-dp/src/afxdp/shared_ops.rs:563-578`**: `ResolvedFlowSessionDecision` correctly integrates the `overdue_skipped` field, enabling explicit downstream control across all 5 state consumers and the `MissingNeighbor` arm.
2. **`userspace-dp/src/session/lookup.rs:62-100`, `:222-250`, `:253-315` & `key.rs:19-26`**: All 5 lookup/reply-match key shapes are specified for flow-cache invalidation, with adopt-time invalidation covering prior alias sets.
3. **`userspace-dp/src/afxdp/session_glue/mod.rs:1157-1196` & `session/lookup.rs:105-128`**: Scoping of the purge parity claim matches the pre-purge lookup ordering. The lingering reverse replica is documented as an absorbing-state residual.
4. **`userspace-dp/src/session/expire.rs:50-57`**: Candidate deadline additions use `saturating_add`, preserving wheel tick calculation invariants.
