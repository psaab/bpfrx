# Codex hostile PLAN review — Tier D issue #946

Source rollout: `rollout-2026-05-04T23-49-37-019df6e6-3f78-7bf3-9683-28d3b5ec7422.jsonl`

---

**Verdict: PLAN-NEEDS-MAJOR**

I would not accept the triage as written. The endpoint may still be “do not implement Phase 2,” but the current rationale overclaims “parent effectively complete.”

Findings:

- `gh issue view 946 --json title,body` could not run here because network to GitHub is blocked, so I verified against the local #946 plans plus current `master` at `4d3c0964`.
- The cited hot-path symbol still exists: [poll_binding_process_descriptor](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:31). The old flat `userspace-dp/src/afxdp.rs` file does not exist, but the target loop survived under `afxdp/poll_descriptor.rs`.
- The hot-path cost is still per-packet: the worker still runs `while let Some(desc) = received.read()` and then stage calls plus flow cache/session/MissingNeighbor work inside that loop: [poll_descriptor.rs:52](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:52).
- The prescribed VPP-style batched pipeline has not shipped under another name. [poll_stages.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_stages.rs:1) explicitly says Phase 1 is “per-packet,” “No batch reordering,” and leaves stages 12+ inline.
- The structural blockers are real: flow-cache lookup mutates LRU/eviction state per lookup, session resolution takes `&mut SessionTable` and may materialize/promote/install sessions, and MissingNeighbor creates/publishes/queues order-coupled state. See [flow_cache.rs:385](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/flow_cache.rs:385), [session_glue/mod.rs:954](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/session_glue/mod.rs:954), and [poll_descriptor.rs:1869](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:1869).

Required fix: rewrite the #946 triage from “Phase 1 shipped, parent effectively complete” to “the original batched-pipeline claim still holds, but Phase 2/full VPP batching is rejected as non-incremental/structurally unsafe without a larger state-snapshot redesign.” That is a major rationale correction, even if the final operational recommendation remains close/wontfix.
