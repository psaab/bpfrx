PLAN NO

1. **BLOCKER — the config-epoch predicate still deletes sessions belonging to a different policy.**

   A usable activation counter exists: snapshots receive a monotonic generation at [manager_generation.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/manager_generation.go:33), and Rust publishes it through `ValidationState` at [snapshot_refresh.rs:397](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:397). The epoch’s existence is not the problem.

   The predicate at [plan.md:1066](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1066) is still `(old numeric policy_id, admission_epoch < activation)`. Numeric policy IDs are positional and explicitly collide across configurations ([policies_ids.go:52](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/policies_ids.go:52), [session/README.md:876](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/README.md:876)).

   Concrete trace: configuration C0 has permitting policy A at ID N and admits a live SNAT flow. C1 inserts B before A, giving B ID N while unchanged A shifts; the existing alias retains N because policy re-resolution updates only the BPF row ([bpf_map/mod.rs:384](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:384)). C2 deletes B; `deletedPolicyRuntimeIDs` returns B’s old ID N ([daemon_policy_invalidate.go:62](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:62)). The A flow is older than C2 and still carries N, so the new predicate deletes a still-permitted flow. Final-holder deletion can release its SNAT allocation and cause a mid-connection re-seed.

   The epoch is also published separately from the policy-bearing `ForwardingState`: the coordinator stores validation then forwarding ([snapshot_refresh.rs:397](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:397)), while workers load validation then forwarding ([loop_body/mod.rs:462](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:462)). A worker can therefore admit under new policy while stamping old validation. The design needs a stable admitting-rule identity and a generation carried in the same immutable policy snapshot.

2. **BLOCKER — the receiver cannot evaluate the new DELETE identity fence.**

   v9.9.4 adds `(origin_process_nonce, flow_incarnation_id)` only to session DELETE messages and then requires comparison with the receiver’s stored incarnation ([plan.md:1103](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1103)). No corresponding SESSION INSTALL/Open carriage is specified.

   Today the install payload ends with `ConfigEpoch` and `RTFlowSessionID` ([sync_protocol.go:192](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go:192)); its decoder ends there too ([sync_protocol.go:485](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go:485)), and `SessionValue` contains neither required identity component ([types.go:89](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/types.go:89)). A receiver-minted incarnation cannot equal the sender’s incarnation.

   Part B therefore requires an additive install identity tail and end-to-end storage contract, not merely a delete tail. This also contradicts the blanket “HA wire unchanged” assertions at [plan.md:1568](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1568), [plan.md:1582](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1582), and [plan.md:2066](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2066).

3. **BLOCKER — mixed-version active/active propagation can delete an authoritative E2.**

   The both-node invalidation premise is correct: the config authority invalidates at [daemon_apply_commit.go:245](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go:245), and the receiving secondary retains `oldActive` and performs the same clear at [daemon_apply_commit.go:326](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go:326).

   Propagation remains node-wide rather than per-entry-owner: owning any RG enables delete sync for every matched forward entry ([daemon_policy_invalidate.go:294](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:294), [daemon_policy_invalidate.go:366](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:366)). Thus a new node owning RG1 can clear a peer-owned RG2 E1 and propagate that delete to an old peer currently owning RG2 with replacement E2.

   Because the sender never installed that peer-owned E1, `takeDeleteGen*` returns zero ([sync_conn_gen.go:176](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:176)). The old peer ignores the identity tail, gen-zero deletes unconditionally ([sync_conn_read.go:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:150), [sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263)), and `DeleteWithCompanionsV4` deletes whatever incarnation is current ([session_store.go:537](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:537)). That removes authoritative E2 and its NAT companions, not merely an E2 standby as claimed at [plan.md:1110](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1110). Mixed-mode propagation needs a per-entry owner gate or negotiated suppression toward legacy peers.

4. **HIGH — permit expiry is not linearized with retain and installation.**

   The new permit transition at [plan.md:920](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:920) leaves permit checking, allocator retain, table insertion, side-map insertion, and terminal outcome as separate operations.

   A command can retain an allocation and stall before side-map insertion. Expiry marks it abandoned and releases the coordinator keeper, but cannot reclaim the token held on the live worker’s stack; RAII runs only on unwind/death ([plan.md:954](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:954), [supervisor.rs:95](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/supervisor.rs:95)). The port can remain pinned indefinitely.

   Conversely, another replica may keep the allocation alive, so an abandoned late executor’s allocation-existence check can still succeed. Current ordering already separates table mutation ([install.rs:322](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:322), [install.rs:427](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:427)) from reservation/publication ([upsert_synced.rs:64](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64)). The design needs a single-winner terminal transition with rollback/drop semantics when `Abandoned` wins.

5. **HIGH — r20-H3’s wrong fence tuple remains normative.**

   The correct tuple appears at [plan.md:1165](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1165), but §9 still specifies `(origin_node_id, session_id)` at [plan.md:1874](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1874). `session_id` is explicitly only a per-worker counter namespace and can collide across nodes ([install.rs:331](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:331)). The acceptance plan therefore still permits implementation of the fence r20 rejected.

6. **MEDIUM — bounded helper scanning and its operative tests remain underspecified.**

   The plan promises ≤1,024-entry chunks at [plan.md:1087](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1087), but the helper’s authoritative tables are single `Mutex<FastMap<…>>` values ([session_manager.rs:12](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/session_manager.rs:12)). Releasing the lock per chunk loses a normal hash-map iterator; rescanning from the start is O(N²), while retaining the iterator holds the global alias lock across the full clear. The existing BPF implementation explicitly avoids this CPU-stall failure with a live cursor ([server_sessions.go:1298](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/grpcapi/server_sessions.go:1298)).

   The test plan also still says claimed commands convert only on worker death ([plan.md:1794](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1794)); it does not exercise permit expiry around retain, side-map insertion, or the final outcome transition.

7. **MEDIUM — the claimed contract sweep did not converge.**

   Section 7 says “No origin flip anywhere” and authority is never packet-driven at [plan.md:1634](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1634), then retains packet-driven `SharedPromote` five lines later; current code performs that flip at [promote.rs:86](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86). The plan also still calls #6522 separately filed at [plan.md:17](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:17) and [plan.md:2107](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2107), despite making its refcount mandatory Part B at [plan.md:983](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:983). Finally, [plan.md:1913](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1913) still promises exactly one Close without the documented two-worker exception.

### Round-20 dispositions

- **r20-B1 — partially resolved.** A usable epoch exists and the named bulk-flip E2 is protected if class revalidation shares the actual alias-delete lock span. The historical policy selector, generation-coherent stamping, and bounded helper scan remain unresolved.
- **r20-B2 — partially resolved.** Both nodes really do invalidate independently and the delete extension is length-compatible. Receiver identity acquisition and legacy-peer owner safety remain unresolved.
- **r20-H3 — not resolved.** The rejected tuple remains in normative §9.
- **r20-H4 — partially resolved.** Permit expiry was added, but it is not atomic with retain/install and cannot bound a retained token on an alive-stuck executor.
- **r20-M5 — partially resolved.** Simple epoch/bulk/full-pair/chunk cases were added; positional-ID reuse, split snapshot publication, permit-expiry interleavings, and scan-work bounds are absent.
- **r20-M6 — partially resolved.** Reverse-synth and normal duplicate wording improved, but authority, wire, #6522, and exactly-once contracts still conflict.
- **r20-LOW — resolved.** The global blind-close claims are now correctly qualified; remaining absolute statements are scoped to zero-trust imported entries.

Part A remains converged: no surviving one-packet-anytime blind-demote trace was found. Part B does not pass confirmation. Its epoch selector can delete a valid SNAT flow, its delete identity is unavailable at the receiver, mixed-version active/active propagation can delete an authoritative replacement, and permit expiry does not safely bound retain/install. Those are concrete live-session, SNAT, and HA harm traces, so v9.9.4 is not implementation-ready.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
