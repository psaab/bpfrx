PLAN NO

Plan citations below are pinned to v9.9.1 commit `2d0395ed6`; the worktree advanced during this review.

1. **BLOCKER — conditional deletion still cannot capture E1’s identity at selection.**

   The new rule requires `(origin_process_nonce, flow_incarnation_id)` to be captured when E1 is selected (`plan.md@2d0395ed6:1023-1040`). But the named selectors receive only BPF `Key + SessionValue`: policy invalidation detaches rows at [daemon_policy_invalidate.go:311](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:311), cluster reconciliation at [session_store.go:626](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:626), and filtered clearing stores detached keys at [server_sessions.go:1234](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/grpcapi/server_sessions.go:1234). The iterator reads the BPF map directly at [maps_session.go:225](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/maps_session.go:225), whose fixed ABI omits the proposed identity fields ([bpf_session_value.go:31](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:31)); v9.9.1 explicitly rejects extending that ABI (`plan.md@2d0395ed6:1000-1007`).

   Consequently, an after-selection alias lookup is racy: Go selects E1, same-key E2 commits, the lookup obtains E2’s identity, and the carried comparison authorizes deleting live E2. The current request is tuple-only at [manager_ha.go:1498](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/manager_ha.go:1498), and Rust reconstructs and deletes by key at [sync_session.rs:29](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/handlers/sync_session.rs:29). For an SNAT flow, this removes E2’s family and can release/re-seed its port.

   The HA continuation is also unfenced: policy invalidation queues a peer key-delete at [daemon_policy_invalidate.go:366](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:366). It consumes the current key generation and creates a newer tombstone ([sync_conn_write.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:69), [sync_conn_gen.go:156](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:156)). If E2 was re-synced after E1’s selection, the receiver deletes E2’s standby at [sync_conn_gen.go:493](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:493).

   Required repair: make the helper authoritative for conditional selection, or introduce an atomic/versioned selection API returning the fence tuple. Carry that selected identity through peer propagation as well. This fence is not implementable through the specified BPF-only selection API.

2. **HIGH — §9 still specifies the wrong fence tuple.**

   Normative text requires `(origin_process_nonce, flow_incarnation_id)` (`plan.md@2d0395ed6:1080-1093`), while §9 still tests `(origin_node_id, session_id)` (`plan.md@2d0395ed6:1746-1747`). The plan itself says `session_id` is separate RT_FLOW correlation state (`plan.md@2d0395ed6:1062-1064`); current code confirms that at [entry.rs:326](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:326). It is a per-worker counter ([session/mod.rs:784](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:784)), not a boot-nonce-qualified incarnation. Following §9 can therefore validate an implementation that mishandles delayed pre-restart E1 deletes.

3. **MEDIUM — bounded replay still lacks explicit late-outcome semantics.**

   Per-allocation pending counts fix the early-`Rejected` keeper-release bug (`plan.md@2d0395ed6:910-922`). A slow command should fail safely after zero-release: canonical-first cleanup removes E1’s alias, so before E2 publication the alias is absent and afterward its incarnation mismatches—even if E2 happens to reuse the same translation. No allocation-generation field is necessary if that ordering remains normative.

   However, v9.9.1 does not define the deadline/late-command state transition, and “supervisor-detected” does not cover a merely hung worker: the supervisor marks death only after panic unwind at [supervisor.rs:98](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/supervisor.rs:98). Specify either a linearizable `Pending → Claimed | Cancelled` permit or that late execution may revalidate but its late outcome is ignored. This is not presently an independent port-swap trace, but the stated bounded-barrier contract is incomplete.

4. **MEDIUM — the new escrow and conditional-delete fences have no acceptance tests.**

   The two-phase order itself fixes join-first destruction: handoff precedes join (`plan.md@2d0395ed6:879-909`). It necessarily adds new machinery because current workers expose only one stop flag ([runtime.rs:20](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/runtime.rs:20)), exit directly at [loop_body/mod.rs:332](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:332), and are immediately joined at [worker_manager.rs:146](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/worker_manager.rs:146). Existing queued upserts contain no hold token ([runtime.rs:408](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/runtime.rs:408)); replay queues need pending-outcome tickets instead. Because launched workers retain the complete queue-map `Arc` ([bringup.rs:598](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:598)), unlaunched queues require explicit rejection rather than relying on `Drop`.

   Section 9 has no tests for quiesce acknowledgement, handoff-before-side-map-drop, partial spawn, multi-replica pending counts, deadline-versus-claim, late outcomes, or E1-selection/E2-replacement conditional deletes.

5. **MEDIUM — the Part-B behavioral contracts remain internally contradictory.**

   - Stale prose says reverse-synth acceptance marks only the reverse entry (`plan.md@2d0395ed6:729-732`), while normative mechanics correctly require atomic forward-family marking (`:1317-1322`, `:1375-1381`).
   - Section 7 says “No origin flip anywhere; authority is never packet-driven” (`:1551-1552`) and immediately retains committed non-close `SharedPromote` (`:1556-1558`). Current code performs that flip at [promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:99). The correct invariant is that no closing packet may drive the flip.
   - The introduction and §11 still describe #6522 as separately filed (`:18-20`, `:1976-1983`), while the body and tests require its holder refcount in Part B (`:954-960`, `:1815-1818`).
   - The design permits a bounded duplicate Close when two workers mark before propagation (`:759-762`), while §9 demands “no duplicates” and “exactly one” (`:1739-1742`, `:1818-1821`).

6. **LOW — blind-close wording is only partially corrected.**

   Section 11 now correctly distinguishes refused and in-window closes (`plan.md@2d0395ed6:1965-1970`), but unqualified “blind close remains inert/refused” claims remain at `:1096-1097` and `:1645`. They conflict with the honest documented acceptance probability at `:1935-1938`.

**Round-18 dispositions**

- **r18-B1 — RESOLVED:** handoff-before-join fixes the destructive ordering; implementation requires a new quiesce/ack/handoff state machine.
- **r18-B2 — NOT RESOLVED:** E1 identity is unavailable at the named BPF-only selection sites, and peer deletion remains key/current-generation based.
- **r18-H3 — PARTIALLY RESOLVED:** per-allocation accounting is fixed; slow-worker cancellation and late outcomes remain underspecified.
- **r18-H4 — NOT RESOLVED:** §9 still names the old tuple.
- **r18-M5 — PARTIALLY RESOLVED:** normative reverse-synth/refcount text improved, but stale contradictory contracts remain.
- **r18-M6 — PARTIALLY RESOLVED:** §11 is fixed, but other absolute claims remain.

Part A remains converged; I found no new blind-demote path through its packet gate. Part B cannot receive final confirmation because its conditional-delete fence cannot acquire the selected incarnation through the current BPF-only APIs, and the subsequent peer delete can still target replacement E2. Make conditional selection helper-authoritative, carry the selected identity through HA deletion, correct §9’s tuple, and add the missing escrow/delete race tests before sign-off.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
