## Plan Review

### Correctness

[CRITICAL-1] The PLAN-KILL decision rule can false-negative because standby passively learns neighbors before promote. A “fast R2” can mean “standby prelearned,” not “cold failover is fixed.” There is no forwarding-active guard on this learn path. Refs: [poll_descriptor/mod.rs:501](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:501), [poll_stages.rs:180](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_stages.rs:180), [poll_stages.rs:183](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_stages.rs:183), [neighbor_dispatch.rs:320](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor_dispatch.rs:320).

[HIGH-1] 5.C.2 is self-limiting for a true “first cold connect.” Promote already runs reverse-session prewarm, and that logic only iterates existing session-indexed keys; a host with no prior session is invisible. Refs: [ha.rs:130](/home/ps/git/bpfrx/userspace-dp/src/afxdp/ha.rs:130), [shared_ops.rs:90](/home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs:90), [shared_ops.rs:95](/home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs:95), [types/forwarding.rs:92](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/forwarding.rs:92).

### Completeness

[HIGH-2] The plan says R1 will prove “buffered vs dropped SYN,” but it does not instrument the silent drop branch. MissingNeighbor buffers only if queue has space; else frame is recycled (drop) with no explicit signal. Refs: [poll_descriptor/mod.rs:2644](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2644), [poll_descriptor/mod.rs:2652](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2652), [poll_descriptor/mod.rs:2734](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2734), [mod.rs:342](/home/ps/git/bpfrx/userspace-dp/src/afxdp/mod.rs:342).

[HIGH-3] R2 proposes clean failover only, but the repo’s failover gate explicitly includes unclean reboot path. Gate-R should include both clean promote and crash/reboot promote before dispositioning production relevance. Refs: [test-failover.sh:188](/home/ps/git/bpfrx/test/incus/test-failover.sh:188), [test-failover.sh:195](/home/ps/git/bpfrx/test/incus/test-failover.sh:195), [CLAUDE.md:106](/home/ps/git/bpfrx/CLAUDE.md:106).

[MEDIUM-1] The timing model assumes 800ms pending-neigh timeout, but runtime may be 2000ms if sysctl checks fail/are slow. Gate-R should capture actual timeout per run to avoid wrong causal inference. Refs: [neighbor_dispatch.rs:99](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor_dispatch.rs:99), [neighbor_dispatch.rs:102](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor_dispatch.rs:102), [forwarding_build/mod.rs:433](/home/ps/git/bpfrx/userspace-dp/src/afxdp/forwarding_build/mod.rs:433), [forwarding_build/mod.rs:474](/home/ps/git/bpfrx/userspace-dp/src/afxdp/forwarding_build/mod.rs:474).

[LOW-1] Repro path naming in the plan is off: `loss-userspace-cluster.env` is under `test/incus/`, not repo root. Refs: [loss-userspace-cluster.env:24](/home/ps/git/bpfrx/test/incus/loss-userspace-cluster.env:24).

### Risks

[HIGH-4] The key H-A/H-B discriminator is under-instrumented. `initial_neighbor_dump` skips non-matching seq messages, but external `ip monitor neigh` cannot prove what xpfd consumed/dropped on its socket. Add internal counters/logging around seq-mismatch skip before Gate-R. Refs: [neighbor.rs:434](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:434), [neighbor.rs:436](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:436), [neighbor.rs:514](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:514), [neighbor.rs:544](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:544).

[MEDIUM-2] 5.B’s “gate on `neighbor_generation >= 1`” is not a valid seededness check because generation is set to 1 on both dump success and dump failure. Refs: [neighbor.rs:514](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:514), [neighbor.rs:516](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:516), [neighbor.rs:519](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:519), [neighbor.rs:520](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:520).

### Alternatives

No additional blocking alternative beyond tightening Gate-R instrumentation and adding crash-failover coverage.

### Feasibility

Current draft is **not PLAN-READY** for Gate-R as written due the blockers above (especially CRITICAL-1, HIGH-2, HIGH-3, HIGH-4).

### Security

No direct security-specific blocker in this research plan.

### Summary

- Critical: 1
- High: 4
- Medium: 2
- Low: 1

Overall: The plan has strong code mapping, but the decision logic can still converge on a wrong fix/PLAN-KILL without stricter instrumentation and failover-case isolation.