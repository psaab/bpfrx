# Codex hostile PLAN review — Tier D issue #949

Source rollout: `rollout-2026-05-04T23-20-40-019df6cb-bd01-7ed3-a553-e139640dfeda.jsonl`

---

**Verdict: PLAN-NEEDS-MAJOR**

Do not accept the triage’s `PLAN-KILL` for #949 as written.

Caveat: `gh issue view 949 --json title,body` was blocked by the sandbox network policy, and the GitHub web endpoint did not expose the issue body. I verified against the triage quote, local #949 plan artifacts, and current master code. The branch is only a doc diff from `origin/master`, so the source checkout is valid for this review.

Findings:

- `dynamic_neighbors` is stale as originally claimed, but the triage overstates it. It is no longer `Arc<Mutex<FastMap<...>>>`; it is `Arc<ShardedNeighborMap>` in [runtime.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/runtime.rs:223). But calling it “lock-free” is false: [sharded_neighbor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/sharded_neighbor.rs:39) is 64 `Mutex` shards, and `get()` locks one shard at [sharded_neighbor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/sharded_neighbor.rs:87). That is a shipped sharded-lock solution, not RCU/immutable state.

- The `shared_sessions` dismissal is not defensible. The triage says it is “install-path only, not hot path,” but the descriptor loop passes `worker_ctx.shared_sessions` into `resolve_flow_session_decision` after flow-cache miss at [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:359). That function calls `lookup_session_across_scopes` at [session_glue/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/session_glue/mod.rs:974), which falls through to `lookup_shared_session` on local miss at [shared_ops.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/shared_ops.rs:410). `lookup_shared_session` takes the mutex at [shared_ops.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/shared_ops.rs:267). Not every packet, but definitely packet-path miss/repair reads.

- The prescribed pattern is only partly shipped. `dynamic_neighbors` PR1 landed, and forwarding/HA snapshots use `ArcSwap` in [ha_state.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/coordinator/ha_state.rs:11). But the local #949 plan explicitly says session maps need PR2, with a composite abstraction and lock ordering, at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/docs/pr/949-sharded-locks/plan.md:21).

- There are real structural constraints, but they argue for a narrower plan, not KILL. Session state is three shared maps plus owner-RG indexes in [session_manager.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/coordinator/session_manager.rs:3) and [types/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/mod.rs:41). `publish_shared_session` updates multiple maps/indexes at [shared_ops.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/shared_ops.rs:621). A mechanical ArcSwap conversion would be risky, but the triage has not proven the remaining refactor is impossible or obsolete.

Recommended revision: change #949 from `KILL` to something like “dynamic_neighbors completed by #955; remaining shared session map contention requires profiling and a composite session-state design, not blanket RCU.”
