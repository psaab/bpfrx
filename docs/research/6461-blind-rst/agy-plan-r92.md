# AGY hostile plan-review — round 92 (v10.9.0)

Reviewer: AGY (direct binary: agy --print-timeout 11m --print, env -C worktree, built-in-file-tools-only). Verdict: SOUND — 10th consecutive AGY YES. Verified both re-scope traces step-by-step against master code (#6599: purge -> install -> Open -> latest-generation-wins overwrite; #6600: publish-before-reserve window with silent steal-refusal), proved the adopt-S2 encoding re-derives D exactly through the wheel's saturating sum, and confirmed the re-scope rationale is identical across all five document locations.

## Verbatim review

SOUND

### Design Document Consistency Review (v10.9.0 — Terminal Cut)

---

### 1. Verification of Re-Scope Traces (#6599 and #6600)

#### (a) Issue #6599 — Transient-Purge / Open Provenance-Integrity Exposure
* **Trace Verification against Master Codebase**:
  1. **Purge Trigger**: A non-closing packet (e.g., a SYN) carrying a translated tuple matching a peer-owned session triggers `purge_translated_synced_hit` in [`userspace-dp/src/afxdp/session_glue/promote.rs:167-207`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L167-L207). It purges the shared entry (`remove_shared_session`), deletes the BPF session map entry, deletes the local table entry, and releases the source NAT allocation.
  2. **Miss Re-Entry & ForwardFlow Install**: The packet re-enters the miss pipeline in [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2449`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2449), installing a fresh `ForwardFlow` via `install_with_protocol_with_origin(..., SessionOrigin::ForwardFlow)`.
  3. **Open Delta Emission**: In [`userspace-dp/src/session/install.rs:234`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L234), `counted && !origin.is_peer_synced()` evaluates to true, pushing an `Open` `SessionDelta` without peer provenance.
  4. **HA Synchronization & Peer Overwrite**: The Go sync writer queues the session in [`pkg/cluster/sync_conn_write.go:53`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go#L53). On receipt, the peer evaluates `installGenGuardV4` in [`pkg/cluster/sync_conn_gen.go:435`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go#L435) and overwrites its local session store in [`pkg/dataplane/session_store.go:257`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go#L257) because the new install carries a higher/fresh generation.

* **Adjudication Verification**:
  - The driving packet is a SYN packet carrying **no FIN or RST flags**. Thus `is_closing(tcp_flags)` is `false` and the demote validator gate cannot engage.
  - The sequence of operations exists verbatim on master today prior to any changes proposed in `plan.md`.
  - Because the sender seeded the SYN packet, the sender legitimately possesses full knowledge of the tuple and state it created. Placement-guessing defenses (such as sequence randomization against blind closes) do not apply to sender-initiated SYN flows.

#### (b) Issue #6600 — HA Import-Window Reservation Race
* **Trace Verification against Master Codebase**:
  1. **Shared Entry Publication**: The HA import thread publishes the imported session to shared tables via `publish_shared_session` in [`userspace-dp/src/afxdp/ha/session_import.rs:115`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs#L115).
  2. **Worker Command Enqueueing**: Afterwards, at [`userspace-dp/src/afxdp/ha/session_import.rs:215`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs#L215), it pushes `WorkerCommand::UpsertSynced(entry.clone())` into worker command queues.
  3. **Port Reservation Lag**: When the worker pops the command, [`userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L64) executes `upsert_synced_with_origin`, and only later at line [`:80`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L80) calls `reserve_synced_source_nat_allocation`.
  4. **Raced Reservation Refusal**: If a local packet arrives in that window and allocates the same NAT port, `reserve_flow` in [`userspace-dp/src/nat/allocator.rs:1636`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L1636) fails at line [`:1682`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L1682) (`!self.shared.occupancy[addr_index].reserve(...)`), returning `false` silently without clearing or failing the imported shared session.

* **Adjudication Verification**:
  - The exposure is packet-class-agnostic and involves no FIN/RST packet.
  - The window exists on master today for any shared-backed entry publication.

---

### 2. Verification of Adopt-S2 Encoding Arithmetic & Wheel Re-Derivation

* **Specification**:
  - `last_seen_ns = now_ns`
  - `expires_after_ns = D.saturating_sub(now_ns)`
  - Where $D = \min(\text{existing probation entry's absolute deadline}, \text{now\_ns} + \text{incoming shared entry's candidate timeout})$.
* **Code Verification**:
  - In [`userspace-dp/src/session/mod.rs:349`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L349), `SessionEntry` stores only `last_seen_ns` and `expires_after_ns` as its timing fields.
  - In [`userspace-dp/src/session/expire.rs:50-57`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L50-L57), `push_to_wheel` computes:
    $$\text{target\_tick\_for}\left(\text{now\_ns},\, \text{entry.last\_seen\_ns.saturating\_add}(\text{entry.expires\_after\_ns})\right)$$
  - Substituting the adopt-S2 values:
    $$\text{now\_ns.saturating\_add}(D\text{.saturating\_sub}(\text{now\_ns})) = D \quad (\text{for } D \ge \text{now\_ns})$$
  - The saturating sum re-derives the exact absolute deadline $D$ into the expiry wheel.
  - In Section 9 ([`plan.md:1937-1938`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1937-L1938)), both K-wins ($D = \text{probation deadline}$) and S2-wins ($D = \text{incoming shared timeout}$) test fixtures are explicitly specified.

---

### 3. Verification of Narrowed §9 Test Claims

* **Purge-Target State Scope**: The byte-identity assertion for peer-synced provenance closes is properly scoped to the purge-target state (shared entry, P1 reservation, shared aliases) ([`plan.md:1959-1961`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1959-L1961)).
* **Accounting Invariant**: The doc correctly notes that a buffered close packet never reaches `account_packet` in [`userspace-dp/src/session/mod.rs:1177`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1177), avoiding false accounting invariant failures on unrelated local rows.
* **Conditional Transmission Rules**: Packet transmission for buffered closes is conditioned on pending-neighbor rules:
  - 4096-next-hop capacity limit in [`userspace-dp/src/afxdp/mod.rs:418`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/mod.rs#L418).
  - ~2s stale-buffer drop in [`userspace-dp/src/afxdp/neighbor_dispatch.rs:187`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs#L187).

---

### 4. Consistency Sweep Across Document Sections

The re-scope rationale for #6599 and #6600 was verified to be strictly identical across all five required locations:
1. **Header History** ([`plan.md:5-7, 76-86`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5-L7)): Documents #6599 and #6600 as pre-existing master exposures out of scope for the demote gate (non-close driving packets).
2. **Section 7** ([`plan.md:1743-1778`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1743-L1778)): Full residual analysis detailing master's verbatim execution paths for both #6599 and #6600.
3. **Section 9** ([`plan.md:1956-1974`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1956-L1974)): Scopes test assertions around closing packet inertness and acknowledges follow-up non-closing packet purge behavior.
4. **Section 10.6.2** ([`plan.md:2232-2247`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2232-L2247)): Lists #6599 and #6600 as pre-existing lifecycle race follow-up candidates.
5. **Section 11 Question 6** ([`plan.md:2363-2367`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2363-L2367)): Re-iterates the re-scope justification for the convergence round.

No retracted design shapes (such as the v10.6.0 skip-the-upsert model or the v9.x RG fence ledger protocol) remain present as active design proposals.

### Summary
The design document v10.9.0 is internally consistent, technically accurate against master, and fully SOUND.
