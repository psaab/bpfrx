# Codex hostile PLAN review — Tier D issue #1127

Source rollout: `rollout-2026-05-04T23-20-39-019df6cb-b719-7aa1-8627-fa3e7bc85656.jsonl`

---

Verdict: PLAN-KILL. I uphold the triage’s KILL for #1127.

No codebase-backed reason to revive it. The old `userspace-dp/src/afxdp.rs` location is gone, and `poll_binding_process_descriptor` now lives at [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:31) with 15 physical parameters, not 31. The 31-to-15 context-object pattern already shipped as `WorkerContext` / `TelemetryContext` in [runtime.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/runtime.rs:207), constructed at the single call site in [lifecycle.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/worker/lifecycle.rs:190). The call is once per RX batch, not once per packet, though the function body loops descriptors.

The vectorized `PacketBatch` premise does not survive the current code shape. `flow_cache.lookup` takes `&mut self` and mutates LRU/hit state on lookup in [flow_cache.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/flow_cache.rs:385). Session resolution takes `&mut SessionTable` and may materialize/promote/install state in [session_glue/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/session_glue/mod.rs:954). Missing-neighbor handling creates the session before buffering the original UMEM frame and pushes it into an ordered `pending_neigh` queue in [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:1869), with FIFO retry semantics documented in [neighbor_dispatch.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/neighbor_dispatch.rs:61). That makes the SIMD/per-stage batch refactor structurally wrong, not merely unimplemented.

Minor doc nit: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/docs/pr/tier-d-triage/plan.md:199) should attribute the 31-to-15 reduction to #945, not “likely before #959 decomposition.” Also, the “sub-1%” SIMD-glue line is unnecessary unless backed by a specific measurement. Neither nit changes the #1127 KILL.

Caveat: `gh issue view 1127 --json title,body` was blocked by the sandbox’s network policy, so I could not independently fetch the live issue body. I verified against the triage’s quoted claim and local historical docs.
