PLAN NO

Part A remains converged: no one-packet-anytime blind-demote trace has returned. Part B still contains a concrete mixed-version authoritative-E2 kill, plus three required fences that remain contradictory or unimplementable as specified.

### Findings

1. **BLOCKER — v9.9.8 protects only old-sender→new-receiver; new-sender→old-receiver still kills authoritative E2.**

   The new immunity is explicitly in the old→new matrix cell at [plan.md:1877](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1877). The opposite cell merely says new→old “tail ignored” at [plan.md:1897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1897). A legacy receiver cannot enforce a rule added to the new receiver.

   Concrete trace:

   - Upgraded A and legacy B both temporarily consider the RG locally primary. A’s sender-side owner gate therefore passes.
   - A holds peer-imported E1 and sends its invalidation delete. Because A did not originally send E1, `takeDeleteGenV4` can return zero at [sync_conn_gen.go:176](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:176); if A did previously send it, the delete instead draws a fresh greater generation through [sync_conn_write.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:69).
   - Legacy B ignores the new identity tail and decodes only the generation at [sync_conn_read.go:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:150).
   - Generation zero is unconditional, while any non-stale generation applies, at [sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263).
   - The accepted key delete reaches [sync_conn_gen.go:493](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:493) and removes B’s locally re-seeded authoritative E2 and NAT companions through [session_store.go:537](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:537).

   This is the exact HA-propagated authoritative kill the issue requires preventing. The new sender must suppress identity-dependent deletes toward a peer that has not negotiated enforcement.

   **Disposition — r21-B3/r22-b: partially resolved. r23-2/r23-a: not resolved.**

2. **BLOCKER — The install/Open identity pipeline is still absent and cannot survive bulk resend.**

   The normative design still specifies only a DELETE identity tail at [plan.md:1172](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1172) and a Close-delta pipeline at [plan.md:1228](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1228). The install tail appears only as an assertion in the §9 matrix. The plan still says the HA wire is unchanged at [plan.md:1649](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1649).

   Current code confirms the missing contract:

   - `SessionDelta` has no nonce/incarnation pair: [entry.rs:283](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:283).
   - `SessionValue` ends at `RTFlowSessionID`: [types.go:89](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/types.go:89).
   - Install encoding and decoding end there: [sync_protocol.go:192](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go:192), [sync_protocol.go:485](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go:485).
   - `SyncedSessionEntry` has no pair: [worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:375).

   More decisively, authoritative bulk and periodic resend reconstruct installs from BPF rows at [sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:95) and [sync_conn_sweep.go:142](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:142). The BPF projection deliberately drops sync-only fields at [bpf_session_value.go:168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:168). Thus even an inferred incremental Open tail is lost on resend unless the plan defines a durable sidecar or makes helper aliases the authoritative bulk source.

   The new local-authority delete check is similarly unstated: Go’s incoming delete has only key and generation, while `ForwardFlow`/`SharedPromote` authority exists only in Rust’s `SessionOrigin` at [entry.rs:215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:215).

   **Disposition — r21-B2/r22-a/r23-1/r23-c: not resolved.**

3. **BLOCKER — The escrow fold chooses the right lifetime, then contradicts it three times.**

   The new rule at [plan.md:920](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:920) is sound in isolation: a coordinator escrow persists across reconcile failure until a later dataplane actually consumes replay. If that rule controls, the previous final-holder loss is closed.

   But the same normative section still says:

   - pending-count zero releases the keeper at [plan.md:931](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:931);
   - `Claimed → Abandoned` releases it at [plan.md:945](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:945); and
   - “abandonment drains the escrow via RAII” at [plan.md:970](/home/ps/git/kimi-xpf/.claude/worktrees/6461-blind-rst/docs/research/6461-blind-rst/plan.md:970).

   Section 9 repeats release-on-zero/release-on-abandonment at [plan.md:1859](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1859).

   If those unchanged clauses control, the prior cut remains: the coordinator records the terminal winner before side-map insertion; completion releases the keeper; a worker panic before insertion drops its retained token during unwind ([supervisor.rs:98](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/supervisor.rs:98)); refcount can reach zero.

   The durable escrow must be specified as a separate coordinator-owned, cross-reconcile object whose lifetime is independent of command permits. Current `PreservedReconcileState` has no such object and is consumed by bring-up at [reconcile/mod.rs:102](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:102) and [reconcile/mod.rs:391](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:391). Post-teardown failures leave the dataplane down rather than automatically restoring old workers ([reconcile/mod.rs:403](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:403)), so “whichever dataplane comes up” requires explicit ownership across later attempts.

   **Disposition — r21-H4/r22-d/r23-4/r23-b: partially resolved.** The new lifetime would work, but the operative contract remains mutually exclusive.

4. **BLOCKER — Content hash plus generation still deletes the wrong logical rule’s flow.**

   The only selector remains “content-addressed rule hash plus forwarding generation” at [plan.md:1113](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1113).

   Under the stated content-only identity:

   - G1: P2 with content C admits NAT flow E.
   - G2: distinct P1 with identical content C is inserted ahead; E remains.
   - G3: P1 is deleted while P2 remains. The deleted set contains `H(C)`, and E carries `H(C)` plus an older generation, so the selector deletes P2’s still-permitted flow. Reap/re-resolution can allocate another pool port.

   Adding rule name/scope to the hash does not make a single hash sufficient: P(C1) may admit E, change to C2 with `policy-rematch` disabled—so E intentionally survives under [daemon_policy_invalidate.go:405](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:405)—then be deleted. The immediate-old configuration knows `H(P,C2)`, while E carries `H(P,C1)`.

   The existing stable logical identity is already `<from>-><to>/<name>` at [policies_ids.go:101](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/policies_ids.go:101). The positional `RuntimePolicyIndex` is separate at [policies_ids.go:112](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/policies_ids.go:112). The selector needs stable logical ID, optional content version, and immutable admission generation as distinct fields.

   The proposed stamp also remains unimplementable:

   - `PolicyRuleSnapshot` has no hash: [protocol_policies.go:266](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/protocol_policies.go:266).
   - `ForwardingState` has no generation: [forwarding.rs:33](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/forwarding.rs:33).
   - `install_epoch` is a worker-local mutation counter ([session/mod.rs:761](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:761)) rewritten on update and promotion ([session/mod.rs:1384](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1384), [session/mod.rs:1642](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1642)).

   **Disposition — r21-B1: partially resolved. r22-c/r23-3/r23-d: not resolved.**

5. **MEDIUM — The claimed stable live cursor remains absent.**

   The plan still says only “CHUNKED identically to today” at [plan.md:1140](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1140) and [plan.md:1903](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1903). It contains no cursor, ordered index, insertion sequence, or scan high-watermark.

   Current shared tables are mutex-protected hash maps ([session_manager.rs:12](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/session_manager.rs:12)); `SessionKey` has no ordering ([key.rs:9](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:9)). The cited Go algorithm explicitly depends on a live BPF key anchor and warns that fresh rescans become O(N²) at [server_sessions.go:1298](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/grpcapi/server_sessions.go:1298).

   **Disposition — r21-M6/r22-e/r23-5: not resolved.** This does not independently drive the named kill verdict, but the claimed fold is not present.

6. **LOW — Contract and test reconciliation remains partial.**

   Section 9 still tests only that numeric collision is disambiguated by epoch at [plan.md:1911](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1911), not same-content rules, modified-then-deleted rules, identity loss on bulk resend, both mixed-version directions, or durable-escrow failure cuts. The blanket unchanged-wire claim remains, as do absolute blind-close statements at [plan.md:1717](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1717) and [plan.md:1999](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1999).

   **Disposition — r21-H5: resolved. r21-M7/r22-f/r23-6: partially resolved.**

### Prior-finding disposition summary

- **Policy selector:** r21-B1 partially resolved; r22-c and r23-3 not resolved.

- **Install identity:** r21-B2, r22-a, and r23-1 not resolved.

- **Mixed-version authoritative delete:** r21-B3 and r22-b partially resolved; r23-2 not resolved.

- **Replay permit/escrow:** r21-H4, r22-d, and r23-4 partially resolved.

- **Fence tuple:** r21-H5 resolved.

- **Live cursor:** r21-M6, r22-e, and r23-5 not resolved.

- **Contract sweep:** r21-M7, r22-f, and r23-6 partially resolved.

- **Deferred to Phase 2:** none; these are Part-B implementation fences.

Part A still eliminates the original blind one-packet-anytime demotion channel. Final confirmation nevertheless fails because an upgraded sender can still propagate a stale delete into a legacy receiver and remove its authoritative E2, directly preserving the HA-kill/SNAT-companion harm; the content-only policy selector supplies a second valid-flow deletion path; and the install-identity and escrow contracts remain non-implementable as written.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
