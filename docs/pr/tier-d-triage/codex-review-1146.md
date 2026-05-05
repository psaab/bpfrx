# Codex hostile PLAN review — Tier D issue #1146

Source rollout: `rollout-2026-05-04T23-53-19-019df6e9-9f79-7482-bd62-61e2473cb89b.jsonl`

---

Verdict: PLAN-NEEDS-MAJOR.

I reject the triage’s PLAN-KILL as written. Caveat: `gh issue view 1146 --json title,body` failed because outbound GitHub access is blocked, so I reviewed the triage-quoted issue claim.

Findings:

- The cited surface is not stale. `poll_descriptor.rs` and `poll_binding_process_descriptor` still exist, and the inner loop is still descriptor-by-descriptor: [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:31), [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:52). Triage should not imply this is only a stale duplicate.

- The hot-path premise partly holds. RX telemetry, metadata parse/classify, flow parse/learn, flow-cache lookup, and session lookup all occur inside that per-packet loop: [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:53), [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:55), [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:92), [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:146), [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:359). The cost may be overstated because common TCP/UDP flow parse uses metadata first, but it is still per-packet.

- The prescribed pattern has only partially shipped. #946 Phase 1 extracted stages 5-11, but the shipped plan explicitly left stages 1 and 2-4 inline and deferred flow-cache/session/MissingNeighbor stages: [plan.md](/home/ps/git/bpfrx/docs/pr/946-pipeline-phase1/plan.md:7), [plan.md](/home/ps/git/bpfrx/docs/pr/946-pipeline-phase1/plan.md:198). That is not equivalent to the issue’s Stage 1-4 vectorized pipeline.

- The vectorized/batched version is legitimately blocked. `FlowCache::lookup` takes `&mut self`, evicts stale entries, mutates LRU, and increments counters: [flow_cache.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/flow_cache.rs:385). MissingNeighbor is also order-coupled: it scans pending probes, creates sessions immediately for SYN-ACK correctness, publishes maps, then queues the exact packet: [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:1906), [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:1923), [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:2038).

So: kill the vectorized/VPP-style batch pipeline, but do not claim the issue is wholly dead or already solved. The triage needs a major rewrite: “duplicate of killed #946 Phase 2 for batching, but the current per-packet decoupling concern still partly survives.”
